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

fn create_app(connection: Arc<InMemoryDatabase<32, Sha256Algorithm>>) -> Router {
    Router::new()
        .route("/root", get(get_root))
        .route("/proof/{id}", get(get_proof))
        .with_state(connection)
}

const TEST_DATA: [(u64, u64); 8] = [(1, 1111), (2, 2222), (3, 3333), (4, 4444), (5, 5555), (6, 6666), (7, 7777), (8, 8888)];
const LEAF_TAG: &[u8; 19] = b"ProofOfReserve_Leaf";
const BRANCH_TAG: &[u8; 21] = b"ProofOfReserve_Branch";

fn create_test_db() -> InMemoryDatabase<32, Sha256Algorithm> {
    InMemoryDatabase::create(TEST_DATA.to_vec(), LEAF_TAG.to_vec(), BRANCH_TAG.to_vec())
}

#[tokio::main]
async fn main() {
    println!("Testing the Merkle root implementation...");
    test_merkle_root();
    
    let bind_address = "0.0.0.0:3000";
    // since our database is immutable, no need to treat it as shared state
    let db = create_test_db();
    let connection = Arc::new(db);
    let app = create_app(connection);
    let listener = tokio::net::TcpListener::bind(bind_address).await.unwrap();

    println!("Starting the server at {}...", bind_address);
    axum::serve(listener, app).await.unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{extract::Request, http, body::Body};
    use merkle::MerkleProofItem;
    use data_encoding::HEXLOWER;
    use serde_json::{json, Value};
    use tower::ServiceExt;
    use http_body_util::BodyExt;

    #[test]
    fn test_merkle_root() {
        let test_values = vec![b"aaa".to_vec(), b"bbb".to_vec(), b"ccc".to_vec(), b"ddd".to_vec(), b"eee".to_vec()];
        let tag = (b"Bitcoin_Transaction").to_vec();
        let tree = MerkleTree::<32, Sha256Algorithm>::build(test_values, tag.clone(), tag.clone());
        let root = tree.get_root();
        let root_hex = HEXLOWER.encode(&root.0);
        assert_eq!(root_hex, "4aa906745f72053498ecc74f79813370a4fe04f85e09421df2d5ef760dfa94b5");
    }

    #[test]
    fn test_merkle_proof_regular() {
        let test_values = vec![b"aaa".to_vec(), b"bbb".to_vec(), b"ccc".to_vec(), b"ddd".to_vec(), b"eee".to_vec()];
        let tag = (b"Bitcoin_Transaction").to_vec();
        let tree = MerkleTree::<32, Sha256Algorithm>::build(test_values, tag.clone(), tag.clone());
        match tree.get_proof(b"aaa".to_vec()) {
            Some(MerkleProof(items)) => {
                assert_eq!(items.len(), 3);
                assert!(matches!(items[0], MerkleProofItem::Right(_)));
                assert!(matches!(items[1], MerkleProofItem::Right(_)));
                assert!(matches!(items[2], MerkleProofItem::Right(_)));
            }
            None => {
                panic!("Anomaly! The proof of a leaf in the tree shouldn't be None.")
            }
        }
    }

    #[test]
    fn test_merkle_proof_pad() {
        let test_values = vec![b"aaa".to_vec(), b"bbb".to_vec(), b"ccc".to_vec(), b"ddd".to_vec(), b"eee".to_vec()];
        let tag = (b"Bitcoin_Transaction").to_vec();
        let tree = MerkleTree::<32, Sha256Algorithm>::build(test_values, tag.clone(), tag.clone());
        match tree.get_proof(b"eee".to_vec()) {
            Some(MerkleProof(items)) => {
                assert_eq!(items.len(), 1);
                assert!(matches!(items[0], MerkleProofItem::Left(_)));
            }
            None => {
                panic!("Anomaly! The proof of a leaf in the tree shouldn't be None.")
            }
        }
    }

    #[test]
    fn test_merkle_proof_nonexistent() {
        let test_values = vec![b"aaa".to_vec(), b"bbb".to_vec(), b"ccc".to_vec(), b"ddd".to_vec(), b"eee".to_vec()];
        let tag = (b"Bitcoin_Transaction").to_vec();
        let tree = MerkleTree::<32, Sha256Algorithm>::build(test_values, tag.clone(), tag.clone());
        assert!(matches!(tree.get_proof(b"ggg".to_vec()), None));
    }

    #[tokio::test]
    async fn test_root_api() {
        let db = create_test_db();
        let connection = Arc::new(db);
        let app = create_app(connection);
        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri("/root")
                    .body(Body::empty())
                    .unwrap()
            ).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body_json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body_json, json!("0xb1231de33da17c23cebd80c104b88198e0914b0463d0e14db163605b904a7ba3"))
    }

    #[tokio::test]
    async fn test_proof_api_normal() {
        let db = create_test_db();
        let connection = Arc::new(db);
        let app = create_app(connection);
        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri("/proof/1")
                    .body(Body::empty())
                    .unwrap()
            ).await.unwrap();
        
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body_json: Value = serde_json::from_slice(&body).unwrap();
        match body_json {
            Value::Object(m) => {
                /* retrieves balance correctly */
                assert_eq!(m.get("balance"), Some(json!(1111)).as_ref());
                let proof = match m.get("proof") {
                    Some(Value::Array(items)) => { items }
                    _ => { panic!("Garbage response!") }
                };
                /* right proof length */
                assert_eq!(proof.len(), 3);
                /* correctly serializes left/right node as 0 or 1 */
                match &proof[0] {
                    Value::Array(item_1) => {
                        assert_eq!(item_1[0], json!(1))
                    }
                    _ => { panic!("Bad proof format!") }
                }
            }
            _ => {
                panic!("Garbage response!")
            }
        }
    }

    #[tokio::test]
    async fn test_proof_api_nonexistent() {
        let db = create_test_db();
        let connection = Arc::new(db);
        let app = create_app(connection);
        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri("/proof/10")
                    .body(Body::empty())
                    .unwrap()
            ).await.unwrap();
        
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}