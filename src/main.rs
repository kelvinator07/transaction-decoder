use serde::Serialize;
use std::io::Read;

#[derive(Debug, Serialize)]
struct Transaction {
    version: u32,
    inputs: Vec<Input>,
    outputs: Vec<Output>,
}

#[derive(Debug, Serialize)]
struct Input {
    txid: String,
    output_index: u32,
    script_sig: String,
    sequence: u32,
}

struct Amount(u64);

impl Amount {
    pub fn to_btc(&self) -> f64 {
        self.0 as f64 / 100_000_000.0
    }
}

#[derive(Debug, Serialize)]
struct Output {
    amount: f64,
    index: u64,
    script_pubkey: String,
}

fn read_compact_size(transaction_bytes: &mut &[u8]) -> u64 {
    let mut compact_size = [0_u8; 1];
    transaction_bytes.read(&mut compact_size).unwrap();

    match compact_size[0] {
        0..=252 => compact_size[0] as u64,
        253 => {
            let mut buffer = [0; 2];
            transaction_bytes.read(&mut buffer).unwrap();
            u16::from_le_bytes(buffer) as u64
        }
        254 => {
            let mut buffer = [0; 4];
            transaction_bytes.read(&mut buffer).unwrap();
            u32::from_le_bytes(buffer) as u64
        }
        255 => {
            let mut buffer = [0; 8];
            transaction_bytes.read(&mut buffer).unwrap();
            u64::from_le_bytes(buffer)
        }
    }

    // if (0..253).contains(&compact_size[0]) {
    //     compact_size[0] as u64
    // } else if compact_size[0] == 253 {
    //     let mut buffer = [0; 2];
    //     transaction_bytes.read(&mut buffer).unwrap();
    //     u16::from_le_bytes(buffer) as u64
    // } else if compact_size[0] == 254 {
    //     let mut buffer = [0; 4];
    //     transaction_bytes.read(&mut buffer).unwrap();
    //     u32::from_le_bytes(buffer) as u64
    // } else {
    //     let mut buffer = [0; 8];
    //     transaction_bytes.read(&mut buffer).unwrap();
    //     u64::from_le_bytes(buffer)
    // }
}

// return type is an integer u32 - 32 bytes
fn read_u32(transaction_bytes: &mut &[u8]) -> u32 {
    let mut buffer = [0; 4]; // 4 bytes = 8 hex chars
    transaction_bytes.read(&mut buffer).unwrap();
    u32::from_le_bytes(buffer) // no semi colon means it will return automatically
}

// return type is an integer u64 - 64 bytes
fn read_amount(transaction_bytes: &mut &[u8]) -> Amount {
    let mut buffer = [0; 8]; // 8 bytes = 16 hex chars
    transaction_bytes.read(&mut buffer).unwrap();
    Amount(u64::from_le_bytes(buffer)) // no semi colon means it will return automatically
}

// param is a mutable reference to a slice i.e &mut &[u8]
// return type is an array [u8; 32] 32 bytes
fn read_txid(transaction_bytes: &mut &[u8]) -> String {
    let mut buffer = [0; 32]; // 32 bytes = 64 hex chars
    transaction_bytes.read(&mut buffer).unwrap();
    buffer.reverse(); // we reverse due to a bug in txid as big endian for human readable format
    hex::encode(buffer) // convert to hex string
}

// we dont know the size at compile time, hence we use a vec of bytes (Vec<u8>) to handle any size
// a vector is smart pointer to some heap allocated data
fn read_script(transaction_bytes: &mut &[u8]) -> String {
    // This first gets the size of what we want to read via read_compact_size, then it read its
    let script_size = read_compact_size(transaction_bytes) as usize; // cast to usize since the size is variable
    let mut buffer = vec![0_u8; script_size];
    transaction_bytes.read(&mut buffer[..]).unwrap(); // dereference coersion, rust implicitly dereferences an object when making a method call
    hex::encode(buffer) // convert to hex string
}

fn main() {
    let transaction_hex = "010000000242d5c1d6f7308bbe95c0f6e1301dd73a8da77d2155b0773bc297ac47f9cd7380010000006a4730440220771361aae55e84496b9e7b06e0a53dd122a1425f85840af7a52b20fa329816070220221dd92132e82ef9c133cb1a106b64893892a11acf2cfa1adb7698dcdc02f01b0121030077be25dc482e7f4abad60115416881fe4ef98af33c924cd8b20ca4e57e8bd5feffffff75c87cc5f3150eefc1c04c0246e7e0b370e64b17d6226c44b333a6f4ca14b49c000000006b483045022100e0d85fece671d367c8d442a96230954cdda4b9cf95e9edc763616d05d93e944302202330d520408d909575c5f6976cc405b3042673b601f4f2140b2e4d447e671c47012103c43afccd37aae7107f5a43f5b7b223d034e7583b77c8cd1084d86895a7341abffeffffff02ebb10f00000000001976a9144ef88a0b04e3ad6d1888da4be260d6735e0d308488ac508c1e000000000017a91476c0c8f2fc403c5edaea365f6a284317b9cdf7258700000000";
    let transaction_bytes = hex::decode(transaction_hex).unwrap(); // 371 bytes == 742 hex characters, 1 byte = 2 hex character
    let mut bytes_slice = transaction_bytes.as_slice();
    let version = read_u32(&mut bytes_slice);
    let input_count = read_compact_size(&mut bytes_slice);

    let mut inputs = vec![];

    for _ in 0..input_count {
        let txid = read_txid(&mut bytes_slice); // txid is 32 bytes == 64 chars
        let output_index = read_u32(&mut bytes_slice); // output_index is 4 bytes = 8 chars = u32 integer
        let script_sig = read_script(&mut bytes_slice); // script_sig length varies, hence it is preceeded by a compact size
        let sequence = read_u32(&mut bytes_slice); // sequence is 4 bytes = u32 integer

        inputs.push(Input {
            txid,
            output_index,
            script_sig,
            sequence,
        });
    }

    let output_count = read_compact_size(&mut bytes_slice);
    let mut outputs = vec![];
    for index in 0..output_count {
        let amount = read_amount(&mut bytes_slice).to_btc(); // amount is 8 bytes = 16 chars = u64 integer
        let script_pubkey = read_script(&mut bytes_slice); // script_pub_key length varies

        outputs.push(Output {
            amount,
            index,
            script_pubkey,
        });
    }

    let transaction = Transaction {
        version,
        inputs,
        outputs,
    };
    println!(
        "Transaction {}",
        serde_json::to_string_pretty(&transaction).unwrap()
    );
}

#[cfg(test)]
mod test {
    use super::read_compact_size;

    #[test]
    fn test_read_compact_size() {
        let mut bytes = [1_u8].as_slice();
        let count = read_compact_size(&mut bytes);
        assert_eq!(count, 1_u64);

        let mut bytes = [253_u8, 0, 1].as_slice();
        let count = read_compact_size(&mut bytes);
        assert_eq!(count, 256_u64);

        let mut bytes = [254_u8, 0, 0, 0, 1].as_slice();
        let count = read_compact_size(&mut bytes);
        assert_eq!(count, 256_u64.pow(3));

        let mut bytes = [255_u8, 0, 0, 0, 0, 0, 0, 0, 1].as_slice();
        let count = read_compact_size(&mut bytes);
        assert_eq!(count, 256_u64.pow(7));

        let hex = "fd204e";
        let decoded = hex::decode(hex).unwrap();
        let mut bytes = decoded.as_slice();
        let count = read_compact_size(&mut bytes);
        let expected_count = 20_000_u64;
        assert_eq!(count, expected_count);
    }
}
