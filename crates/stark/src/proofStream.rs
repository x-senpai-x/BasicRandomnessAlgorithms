use serde::{Serialize, Deserialize};
pub struct ProofStream {
    pub objects: Vec<u8>,
    pub position: usize,
}
impl ProofStream {
    pub fn new(objects: Vec<u8>) -> Self {
        ProofStream {
            objects,
            position: 0,
        }
    }
    pub fn push(&mut self, object: u8) {
        self.objects.push(object);
    }
    pub fn pop(&mut self) -> Option<u8> {
        if self.position < self.objects.len() {
            let obj = self.objects[self.position];
            self.position += 1;
            Some(obj)
        } else {
            None
        }
    }
    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap()
    }
    pub fn deserialize(data: &[u8]) -> Self {
        bincode::deserialize(data).unwrap()
    }
    pub fn prover_fiat
}