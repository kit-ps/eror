#!/bin/bash
set -euo pipefail

onion_size() {
    path_len=$1
    sed -i "s/pub const MAX_PATH_LENGTH: usize = .\+;/pub const MAX_PATH_LENGTH: usize = $path_len;/" sphinx/src/constants.rs
    cargo +nightly run --example=onion_sizes -- $path_len
    sed -i "s/pub const MAX_PATH_LENGTH: usize = .\+;/pub const MAX_PATH_LENGTH: usize = 5;/" sphinx/src/constants.rs
}

echo "Path length | Payload size [bytes] | EROR Onion size [bytes] | Sphinx Onion size [bytes]"
echo "============+======================+=========================+=========================="
for i in {1..10} ; do
    onion_size $i 2>/dev/null
    echo "------------+----------------------+-------------------------+--------------------------"
done
