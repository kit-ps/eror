use std::{collections::HashMap, time::Duration};

use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use rand::prelude::*;

static PAYLOAD: &[u8] = include_bytes!("payload.txt");

fn payload_sizes() -> impl Iterator<Item = usize> {
    (128..=1024).step_by(128)
}

fn path_lengths() -> impl Iterator<Item = usize> {
    1..=5
}

fn bench_eror(c: &mut Criterion) {
    use eror::{pki::Pki, primitives::EcPrimitives, *};

    let mut rng = rand::thread_rng();

    let primitives = EcPrimitives;
    let mut pki = Pki::<EcPrimitives>::new();
    let mut private_keys = HashMap::new();
    for _ in 0..10 {
        let address: Address = rng.gen();
        let (sk, pk) = primitives.generate_keypair(&mut rng);
        pki.insert(address, pk);
        private_keys.insert(address, sk);
    }
    let addresses = pki.keys().keys().cloned().collect::<Vec<_>>();

    let format = OnionFormat::new(primitives, pki, 5);

    let mut group = c.benchmark_group("eror/form_onion");
    for payload_size in payload_sizes() {
        let payload = &PAYLOAD[..payload_size];
        group.throughput(Throughput::Bytes(payload_size as u64));
        group.bench_function(format!("{}-bytes", payload_size), |b| {
            b.iter(|| format.form_onion(&mut rng, &addresses[0..5], &addresses[5..10], payload))
        });
    }
    group.finish();

    let mut group = c.benchmark_group("eror/form_onion");
    for path_len in path_lengths() {
        let payload = &PAYLOAD[..128];
        let path_forward = &addresses[0..path_len];
        let path_backward = &addresses[5..5 + path_len];
        group.bench_function(format!("{}-hops", path_len), |b| {
            b.iter(|| format.form_onion(&mut rng, path_forward, path_backward, payload))
        });
    }
    group.finish();

    let mut group = c.benchmark_group("eror/proc_onion");
    for payload_size in payload_sizes() {
        let private_key = private_keys[&addresses[0]];
        let onion = format
            .form_onion(
                &mut rng,
                &addresses[0..5],
                &addresses[5..10],
                &PAYLOAD[..payload_size],
            )
            .unwrap()
            .0;
        group.throughput(Throughput::Bytes(payload_size as u64));
        group.bench_function(format!("{}-bytes", payload_size), |b| {
            b.iter_batched(
                || onion.clone(),
                |onion| format.proc_onion_without_reply(&mut rng, &private_key, onion),
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

fn bench_sphinx(c: &mut Criterion) {
    use sphinx_packet::{
        crypto,
        header::delays::Delay,
        payload::PAYLOAD_OVERHEAD_SIZE,
        route::{Destination, DestinationAddressBytes, Node, NodeAddressBytes},
        SURBMaterial, SphinxPacket, SphinxPacketBuilder,
    };

    fn sphinx_surb_size(path_len: usize) -> usize {
        let nodes = (0..path_len)
            .map(|_| {
                let address = NodeAddressBytes::from_bytes(rand::thread_rng().gen());
                let (_, pub_key) = crypto::keygen();
                Node { address, pub_key }
            })
            .collect::<Vec<_>>();
        let delays = vec![Delay::new_from_nanos(0); path_len];
        let destination = Destination::new(
            DestinationAddressBytes::from_bytes(Default::default()),
            Default::default(),
        );
        SURBMaterial::new(nodes, delays, destination)
            .construct_SURB()
            .unwrap()
            .to_bytes()
            .len()
    }

    let mut rng = rand::thread_rng();
    let mut nodes = HashMap::new();
    let mut private_keys = HashMap::new();
    for _ in 0..10 {
        let address = NodeAddressBytes::from_bytes(rng.gen());
        let (priv_key, pub_key) = crypto::keygen();
        nodes.insert(
            address.clone(),
            Node {
                address: address.clone(),
                pub_key,
            },
        );
        private_keys.insert(address, priv_key);
    }

    let delays = vec![Delay::new_from_nanos(0); 10];
    let destination = Destination::new(DestinationAddressBytes::from_bytes(rng.gen()), rng.gen());

    let route = nodes.values().cloned().collect::<Vec<_>>();

    let mut group = c.benchmark_group("sphinx/form_onion");
    for payload_size in payload_sizes() {
        let builder = SphinxPacketBuilder::new()
            .with_payload_size(payload_size + sphinx_surb_size(5) + PAYLOAD_OVERHEAD_SIZE);
        let payload = &PAYLOAD[..payload_size];
        group.throughput(Throughput::Bytes(payload_size as u64));
        group.bench_function(format!("{}-bytes", payload_size), |b| {
            b.iter(|| {
                // To make a fair comparison, we compute a Sphinx header and an accompanying SURB,
                // as the EROR also accounts for the reply.
                let surb_route = route[5..10].to_vec();
                let delay = delays[5..10].to_vec();
                let surb = SURBMaterial::new(surb_route, delay, destination.clone())
                    .construct_SURB()
                    .unwrap();
                let mut payload = payload.to_vec();
                payload.extend(surb.to_bytes());
                builder
                    .build_packet(payload, &route[..5], &destination, &delays[..5])
                    .unwrap();
            });
        });
    }
    group.finish();

    let mut group = c.benchmark_group("sphinx/form_onion");
    for path_len in path_lengths() {
        let builder = SphinxPacketBuilder::new()
            .with_payload_size(128 + sphinx_surb_size(path_len) + PAYLOAD_OVERHEAD_SIZE);

        let payload = &PAYLOAD[..128];
        let path_forward = &route[0..path_len];
        let path_backward = &route[5..5 + path_len];
        group.bench_function(format!("{}-hops", path_len), |b| {
            b.iter(|| {
                let surb_route = path_backward.to_vec();
                let delay = delays[5..5 + path_len].to_vec();
                let surb = SURBMaterial::new(surb_route, delay, destination.clone())
                    .construct_SURB()
                    .unwrap();
                let mut payload = payload.to_vec();
                payload.extend(surb.to_bytes());
                builder
                    .build_packet(payload, path_forward, &destination, &delays[..path_len])
                    .unwrap();
            });
        });
    }
    group.finish();

    let mut group = c.benchmark_group("sphinx/proc_onion");
    for payload_size in payload_sizes() {
        let builder = SphinxPacketBuilder::new()
            .with_payload_size(payload_size + sphinx_surb_size(5) + PAYLOAD_OVERHEAD_SIZE);

        let private_key = &private_keys[&route[0].address];

        let surb_route = route[..5].to_vec();
        let delay = delays[5..10].to_vec();
        let surb = SURBMaterial::new(surb_route, delay, destination.clone())
            .construct_SURB()
            .unwrap();
        let mut payload = PAYLOAD[..payload_size].to_vec();
        payload.extend(surb.to_bytes());
        let onion = builder
            .build_packet(payload, &route[..5], &destination, &delays[..5])
            .unwrap();

        group.throughput(Throughput::Bytes(payload_size as u64));
        group.bench_function(format!("{}-bytes", payload_size), |b| {
            b.iter_batched(
                || SphinxPacket::from_bytes(&onion.to_bytes()).unwrap(),
                |onion| onion.process(private_key).unwrap(),
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .measurement_time(Duration::from_secs(6));
    targets = bench_eror, bench_sphinx
}
criterion_main!(benches);
