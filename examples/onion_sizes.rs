use eror::{pki::Pki, primitives::EcPrimitives, Address, Onion, OnionFormat};
use rand::Rng;

fn generate_onion(path_lengths: u32, payload_size: u64) -> Onion<EcPrimitives> {
    let primitives = EcPrimitives;

    // Generate as many keys as we need
    let mut pki = Pki::<EcPrimitives>::new();
    for _ in 0..2 * path_lengths {
        let address: Address = rand::thread_rng().gen();
        let (_sk, pk) = primitives.generate_keypair(rand::thread_rng());
        pki.insert(address, pk);
    }
    let addresses = pki.keys().keys().cloned().collect::<Vec<_>>();

    let format = OnionFormat::new(primitives, pki, path_lengths);

    let payload = vec![0; payload_size.try_into().unwrap()];
    let path_lengths = path_lengths.try_into().unwrap();

    format
        .form_onion(
            rand::thread_rng(),
            &addresses[..path_lengths],
            &addresses[path_lengths..],
            &payload,
        )
        .unwrap()
        .0
}

fn generate_sphinx_onion(path_length: usize, payload_size: usize) -> sphinx_packet::SphinxPacket {
    use sphinx_packet::{
        crypto,
        header::delays::Delay,
        payload::PAYLOAD_OVERHEAD_SIZE,
        route::{Destination, DestinationAddressBytes, Node, NodeAddressBytes},
        SphinxPacketBuilder,
    };

    fn sphinx_surb_size(_path_len: usize) -> usize {
        // We assume that a SURB has the same length as a Sphinx header, as per the original Sphinx
        // paper.
        sphinx_packet::header::HEADER_SIZE
    }

    let mut rng = rand::thread_rng();
    let route = (0..2 * path_length)
        .map(|_| {
            let address = NodeAddressBytes::from_bytes(rand::thread_rng().gen());
            let (_, pub_key) = crypto::keygen();
            Node { address, pub_key }
        })
        .collect::<Vec<_>>();

    let delays = vec![Delay::new_from_nanos(0); 2 * path_length];
    let destination = Destination::new(DestinationAddressBytes::from_bytes(rng.gen()), rng.gen());

    let surb_size = sphinx_surb_size(path_length);
    let builder = SphinxPacketBuilder::new()
        .with_payload_size(payload_size + surb_size + PAYLOAD_OVERHEAD_SIZE);
    let payload = vec![0u8; payload_size + surb_size];
    builder
        .build_packet(
            payload,
            &route[..path_length],
            &destination,
            &delays[..path_length],
        )
        .unwrap()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "Path length | Payload size [bytes] | EROR Onion size [bytes] | Sphinx Onion size [bytes]"
    );
    println!(
        "============+======================+=========================+=========================="
    );
    for path_length in 1..10 {
        for payload_size in &[0, 128, 256, 512, 1024, 2048, 4096] {
            let onion = generate_onion(path_length, *payload_size);
            let serialized = bincode::serialize(&onion)?;

            let sphinx_size = if usize::try_from(path_length).unwrap() <= sphinx_packet::constants::MAX_PATH_LENGTH {
                let sphinx_onion = generate_sphinx_onion(
                    path_length.try_into().unwrap(),
                    (*payload_size).try_into().unwrap(),
                );
                let sphinx_serialized = sphinx_onion.to_bytes();
                sphinx_serialized.len().to_string()
            } else {
                "---".to_string()
            };
            println!(
                "{:<11} | {:<20} | {:<23} | {:<25}",
                path_length,
                payload_size,
                serialized.len(),
                sphinx_size,
            );
        }
        println!("------------+----------------------+-------------------------+--------------------------");
    }
    Ok(())
}
