use std::{
	collections::{BTreeMap, HashSet},
	error::Error,
	fs::{copy, create_dir_all, metadata},
	io::Write,
	path::{Path, PathBuf},
	sync::{Arc, Mutex},
};

use arc_swap::ArcSwap;
use data_encoding::HEXLOWER;
use futures_util::TryStreamExt; // For mongodb cursor
use infer;
use mime;
use mongodb::{Client, Collection, bson::doc, options::ClientOptions};
use ring::digest::{Context, SHA256};
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

mod id;
pub use id::{Id, IdHint};

#[derive(Serialize, Deserialize)]
struct FileRecord
{
	name: String,
	digest: String,
	mime_type: String,
	tags: Vec<String>,
}

#[derive(Clone)]
pub struct InFile
{
	name: String,
	handle: Arc<Mutex<NamedTempFile>>,
	digest: Context,
	is_utf8: bool,
	tags: HashSet<String>,
}

impl InFile
{
	fn new(name: impl AsRef<str>) -> Result<InFile, Box<dyn Error>>
	{
		Ok(InFile {
			name: name.as_ref().to_string(),
			handle: Arc::new(Mutex::new(NamedTempFile::new()?)),
			digest: Context::new(&SHA256),
			is_utf8: true,
			tags: HashSet::<String>::new(),
		})
	}

	pub fn name(&self) -> &String { &self.name }

	pub fn digest(&self) -> String
	{
		let digest = self.digest.clone().finish();
		HEXLOWER.encode(digest.as_ref())
	}

	pub fn id(&self) -> Id { Id::new(self.digest()).unwrap() }

	pub fn add_tag(self: &mut Self, tag: String) -> bool { self.tags.insert(tag) }

	pub fn write_all(self: &mut Self, buffer: &[u8]) -> std::io::Result<()>
	{
		self.is_utf8 = self.is_utf8 && std::str::from_utf8(buffer).is_ok();
		self.digest.update(buffer);
		self.handle.lock().unwrap().write_all(buffer)
	}
}

#[derive(Clone)]
pub struct OutFile
{
	pub name: String,
	pub mime_type: mime::Mime,
	pub path: PathBuf,
	id: id::Id,
	pub tags: Vec<String>,
}

impl OutFile
{
	fn new<T: AsRef<Path>>(shared_folder: T, record: FileRecord, id: id::Id) -> OutFile
	{
		OutFile {
			name: record.name,
			mime_type: record
				.mime_type
				.parse::<mime::Mime>()
				.unwrap_or(mime::APPLICATION_OCTET_STREAM),
			path: shared_folder.as_ref().join(&record.digest),
			id,
			tags: record.tags,
		}
	}

	pub fn id(&self) -> Id { self.id }

	pub fn is_plain_text(self: &Self) -> bool
	{
		match (self.mime_type.type_(), self.mime_type.subtype())
		{
			(mime::TEXT, mime::PLAIN) => true,
			_ => false,
		}
	}
}

type RecordCache = std::collections::BTreeMap<id::Id, OutFile>;

pub struct FileDB
{
	client: Client,
	cache: ArcSwap<RecordCache>,
	pub shared_folder: PathBuf,
}

impl FileDB
{
	pub const DEFAULT_DB_NAME: &'static str = "FileDB";
	pub const DEFAULT_COLLECTION_NAME: &'static str = "SharedFiles";

	fn client_to_db(client: &Client) -> Collection<FileRecord>
	{
		client
			.database(Self::DEFAULT_DB_NAME)
			.collection(Self::DEFAULT_COLLECTION_NAME)
	}

	fn db(&self) -> Collection<FileRecord> { Self::client_to_db(&self.client) }

	async fn load_cache(
		client: &Client,
		shared_folder: impl AsRef<Path>,
	) -> Result<RecordCache, Box<dyn Error>>
	{
		let mut cursor = Self::client_to_db(client).find(doc! {}, None).await?;

		let mut cache = BTreeMap::new();

		while let Some(record) = cursor.try_next().await?
		{
			let id = id::Id::new(&record.digest)?;
			cache.insert(id, OutFile::new(shared_folder.as_ref(), record, id));
		}

		Ok(cache)
	}

	pub async fn new<T: AsRef<Path>>(
		shared_folder: T,
		connexion: impl AsRef<str>,
	) -> Result<FileDB, Box<dyn Error>>
	{
		let options = ClientOptions::parse(connexion).await?;
		create_dir_all(&shared_folder)?;
		let md = metadata(&shared_folder)?;

		if md.permissions().readonly()
		{
			Err(format!(
				"Not enough permissions on shared folder[{}]",
				shared_folder.as_ref().display()
			)
			.into())
		}
		else
		{
			let client = Client::with_options(options)?;
			let cache = ArcSwap::new(Arc::new(
				Self::load_cache(&client, shared_folder.as_ref()).await?,
			));
			Ok(FileDB {
				client,
				cache,
				shared_folder: shared_folder.as_ref().to_path_buf(),
			})
		}
	}

	pub fn new_file(name: impl AsRef<str>) -> Result<InFile, Box<dyn Error>> { InFile::new(name) }

	pub async fn save(self: &Self, file: InFile) -> Result<Id, Box<dyn Error + Send + Sync>>
	{
		let digest = file.digest.finish();
		let encoded_digest = HEXLOWER.encode(digest.as_ref());

		let path_copy = {
			let guard = file.handle.lock();
			guard.unwrap().path().to_path_buf()
		};

		let mime_type: mime::Mime = if file.is_utf8
		{
			mime::TEXT_PLAIN_UTF_8
		}
		else
		{
			match infer::get_from_path(path_copy.as_path())?
			{
				Some(inferred) => inferred.mime_type().parse()?,
				None => mime::APPLICATION_OCTET_STREAM,
			}
		};

		let tags: Vec<String> = file.tags.into_iter().collect();

		let file_record = FileRecord {
			name: file.name.clone(),
			digest: encoded_digest.clone(),
			mime_type: mime_type.to_string(),
			tags: tags.clone(),
		};

		self.db().insert_one(file_record, None).await?;

		let result_path = self.shared_folder.join(encoded_digest);

		copy(path_copy, result_path.as_path())?;

		let id = id::Id::from_digest(digest.as_ref());

		let mut cache = (*self.cache.load_full()).clone();

		cache.insert(
			id,
			OutFile {
				id,
				name: file.name,
				path: result_path,
				mime_type,
				tags,
			},
		);

		self.cache.store(Arc::new(cache));

		Ok(id)
	}

	pub async fn get(self: &Self, digest: id::Id) -> Result<Option<OutFile>, Box<dyn Error>>
	{
		match self
			.db()
			.find_one(
				doc! {
					"digest": digest.to_string()
				},
				None,
			)
			.await?
		{
			Some(record) => Ok(Some(OutFile::new(&self.shared_folder, record, digest))),
			None => Ok(None),
		}
	}

	pub async fn search(self: &Self, prefix: id::IdHint) -> Result<Vec<OutFile>, Box<dyn Error>>
	{
		let mut result: Vec<OutFile> = Vec::new();

		let mut cursor = self
			.db()
			.find(
				doc! {
					"digest": mongodb::bson::Regex {
						pattern: format!("^{}", prefix),
						options: "".to_owned(),
					}
				},
				None,
			)
			.await?;

		while let Some(record) = cursor.try_next().await?
		{
			let id = id::Id::new(&record.digest)?;
			result.push(OutFile::new(&self.shared_folder, record, id));
		}

		Ok(result)
	}

	pub async fn delete(self: &Self, digest: id::Id) -> Result<(), Box<dyn Error>>
	{
		if let Some(deleted) = self
			.db()
			.find_one_and_delete(
				doc! {
					"digest": digest.to_string()
				},
				None,
			)
			.await?
		{
			tokio::fs::remove_file(self.shared_folder.join(&deleted.digest))
				.await
				.ok();

			if let Ok(id) = id::Id::new(deleted.digest)
			{
				let mut cache = (*self.cache.load_full()).clone();
				cache.remove(&id);
				self.cache.store(Arc::new(cache));
			}
		}

		Ok(())
	}

	pub async fn update(self: &Self, digest: id::Id, file: InFile) -> Result<Id, Box<dyn Error + Send + Sync>>
	{
		match self.save(file).await
		{
			Ok(new_id) =>
			{
				if new_id != digest
				{
					let _ = self.delete(digest).await;
				}
				Ok(new_id)
			},
			Err(e) => Err(e)
		}
	}

	pub fn get_from_cache(self: &Self, digest: id::Id) -> Option<OutFile>
	{
		self.cache.load_full().get(&digest).cloned()
	}

	pub fn all_from_cache(self: &Self) -> Vec<OutFile>
	{
		let cache = self.cache.load_full();
		let mut result = Vec::new();

		for (_, out_file) in cache.iter()
		{
			result.push(out_file.clone());
		}

		result
	}

	pub fn search_in_cache(self: &Self, hint: id::IdHint) -> Vec<OutFile>
	{
		let cache = self.cache.load_full();
		let mut result = Vec::new();

		for (id, out_file) in cache.iter()
		{
			if hint < *id
			{
				break;
			}

			if hint == *id
			{
				result.push(out_file.clone());
			}
		}

		result
	}

	pub fn match_tag_in_cache(self: &Self, tag: String) -> Vec<OutFile>
	{
		let cache = self.cache.load_full();
		let mut result = Vec::new();

		for (_, out_file) in cache.iter()
		{
			let mut found = false;

			for t in &out_file.tags
			{
				if *t == tag
				{
					found = true;
					break;
				}
			}

			if found
			{
				result.push(out_file.clone());
			}
		}

		result
	}
}
