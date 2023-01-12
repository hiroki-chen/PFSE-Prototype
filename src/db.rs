//! This module mainly implements a context that contains a database instance.
//! We use MongoDB as our backend database.

use std::marker::PhantomData;

use mongodb::{
    bson::Document,
    sync::{Client, Cursor, Database},
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::Result;

/// A sample data store.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Data {
    pub id: usize,
    pub data: String,
}

/// A context that can be used to perform database-related operations such as insert, search.
///
/// Note that `T` must derive `Serialize` and `Deserialize` so that it can be stored in MongoDB.
#[derive(Debug, Clone)]
pub struct Connector<T>
where
    T: Serialize + DeserializeOwned,
{
    /// The database instance.
    database: Database,
    /// A marker.
    _marker: PhantomData<T>,
    /// Should we drop the database on `drop`.
    drop: bool,
}

impl<T> Connector<T>
where
    T: Serialize + DeserializeOwned,
{
    pub fn new(address: &str, db_name: &str, drop: bool) -> Result<Self> {
        let client = Client::with_uri_str(address)?;

        Ok(Self {
            database: client.database(db_name),
            _marker: PhantomData,
            drop,
        })
    }

    /// Get the name of the current database.
    pub fn name(&self) -> &str {
        self.database.name()
    }

    /// Search a given document in the collection.
    pub fn search(
        &self,
        document: Document,
        collection_name: &str,
    ) -> Result<Cursor<T>> {
        let collection = self.database.collection(collection_name);
        Ok(collection.find(document, None)?)
    }

    /// Insert documents into the collection.
    pub fn insert(
        &self,
        document: Vec<T>,
        collection_name: &str,
    ) -> Result<()> {
        let collection = self.database.collection(collection_name);
        collection.insert_many(document, None)?;

        Ok(())
    }
}

impl<T> Drop for Connector<T>
where
    T: Serialize + DeserializeOwned,
{
    /// Automatically delete the current database.
    fn drop(&mut self) {
        if self.drop {
            self.database.drop(None).unwrap_or_default();
        }
    }
}
