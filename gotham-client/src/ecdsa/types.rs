use kms::ecdsa::two_party::MasterKey2;
use curv::BigInt;

#[derive(Serialize, Deserialize)]
pub struct PrivateShare {
    pub id: String,
    pub master_key: MasterKey2
}

impl PrivateShare {
    pub fn get_child(&self, path: Vec<BigInt>) -> PrivateShare {
        let child_key = self.master_key.get_child(path);
        PrivateShare {
            id: self.id.clone(),
            master_key: child_key
        }
    }
}