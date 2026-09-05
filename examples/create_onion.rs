use std::collections::HashMap;

use eror::{pki::Pki, primitives::EcPrimitives, Address, OnionFormat, ProcessedOnion};
use rand::Rng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let primitives = EcPrimitives;
    let mut pki = Pki::<EcPrimitives>::new();
    let mut private_keys = HashMap::new();
    for _ in 0..10 {
        let address: Address = rand::thread_rng().gen();
        let (sk, pk) = primitives.generate_keypair(rand::thread_rng());
        pki.insert(address, pk);
        private_keys.insert(address, sk);
    }
    let addresses = pki.keys().keys().cloned().collect::<Vec<_>>();

    let format = OnionFormat::new(primitives, pki, 5);

    println!("Requesting onion for:");
    println!("            forward = {:?}", &addresses[..5]);
    println!("            backward = {:?}", &addresses[5..10]);

    //let (mut onion, shares) = format.onionize(rand::thread_rng(), &addresses[..5], Payload::Fixed(b"crypto"))?;
    let (mut current_onion, expected_reply) = format.form_onion(
        rand::thread_rng(),
        &addresses[..5],
        &addresses[5..10],
        b"crypto",
    )?;
    let mut current_address = addresses[0];

    loop {
        println!();
        println!("Simulating mix node {:?}", current_address);
        let private_key = private_keys.get(&current_address).unwrap();

        let proc = format.proc_onion(
            rand::thread_rng(),
            private_key,
            |i| if i == expected_reply.identifier {
                Some(expected_reply.tag)
            } else {
                None
            },
            current_onion.clone(),
        )?;

        match proc {
            ProcessedOnion::Hop {
                next_address,
                next_onion,
            } => {
                current_onion = next_onion;
                current_address = next_address;
            }
            ProcessedOnion::Sender { payload, .. } => {
                let text = String::from_utf8_lossy(&payload);
                println!(
                    "I am the original sender, I have received a reply: {}",
                    text
                );
                break;
            }
            ProcessedOnion::Receiver {
                payload,
            } => {
                let text = String::from_utf8_lossy(&payload);
                println!("I am the receiver, I have received: {}", text);

                (current_onion, current_address) =
                    format.reply_onion(rand::thread_rng(), &private_key, current_onion, b"replyy")?;
            }
        }
    }

    Ok(())
}
