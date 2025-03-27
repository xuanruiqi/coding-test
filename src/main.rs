mod merkle;
mod db;
use merkle::{MerkleTree, MerkleProof, MerkleRoot, Sha256Algorithm};
use db::{UserDatabase, InMemoryDatabase};
use axum::{
    debug_handler, extract::{Json, Path, State}, http::StatusCode, response::{IntoResponse, Response}, routing::get, Router};
use std::sync::Arc;
use serde::Serialize;

fn test_merkle_root() {
    let test_values = vec![b"aaa".to_vec(), b"bbb".to_vec(), b"ccc".to_vec(), b"ddd".to_vec(), b"eee".to_vec()];
    let tag = (b"Bitcoin_Transaction").to_vec();
    let tree = MerkleTree::<32, Sha256Algorithm>::build(test_values, tag.clone(), tag.clone());
    let root = tree.get_root();
    println!("{}", serde_json::to_string(&root).unwrap());
}

fn test_merkle_proof() {
    let test_values = vec![b"aaa".to_vec(), b"bbb".to_vec(), b"ccc".to_vec(), b"ddd".to_vec(), b"eee".to_vec()];
    let tag = (b"Bitcoin_Transaction").to_vec();
    let tree = MerkleTree::<32, Sha256Algorithm>::build(test_values, tag.clone(), tag.clone());
    let proof = tree.get_proof(b"ccc".to_vec());
    match proof {
        Some(proof) => {
            let proof_json = serde_json::to_string(&proof).unwrap();
            println!("{}", proof_json);
        },
        None => {
            println!("No proof found.");
        }
    }
}

enum Error { UserNotFound(u64) }

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        match self {
            Error::UserNotFound(user_id) => {
                (StatusCode::NOT_FOUND, format!("User with ID {} not found.", user_id)).into_response()
            }
        }
    }
}

impl From<u64> for Error {
    fn from(user_id: u64) -> Self {
        Error::UserNotFound(user_id)
    }
}


async fn get_root(State(db): State<Arc<InMemoryDatabase<32, Sha256Algorithm>>>) -> Json<MerkleRoot<32>> {
    let root = db.get_root();
    Json(root)
}

#[derive(Serialize)]
struct ProofResponse {
    balance: u64,
    proof: MerkleProof<32>,
}

#[debug_handler(state = Arc<InMemoryDatabase<32, Sha256Algorithm>>)]
async fn get_proof(
    State(db): State<Arc<InMemoryDatabase<32, Sha256Algorithm>>>,
    Path(user_id): Path<u64>
) -> Result<Json<ProofResponse>, Error> {
    let balance = db.get_balance(user_id).ok_or(Error::UserNotFound(user_id))?;
    let proof = db.get_proof(user_id).unwrap();
    Ok(Json(ProofResponse { balance, proof }))
}

#[tokio::main]
async fn main() {
    println!("Testing the Merkle root implementation...");
    test_merkle_root();
    println!("Testing the Merkle proof implementation...");
    test_merkle_proof();
    println!("Starting the server...");
    let user_data = vec![(1, 1111), (2, 2222), (3, 3333), (4, 4444),
    (5, 5555), (6, 6666), (7, 7777), (8, 8888)];
    let leaf_tag = b"ProofOfReserve_Leaf".to_vec();
    let branch_tag = b"ProofOfReserve_Branch".to_vec();
    // since our database is immutable, no need to treat it as shared state
    let db = InMemoryDatabase::<32, Sha256Algorithm>::create(user_data, leaf_tag, branch_tag);
    let state = Arc::new(db);
    let app = Router::new()
        .route("/root", get(get_root))
        .route("/proof/{id}", get(get_proof))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
