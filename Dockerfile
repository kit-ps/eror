FROM rust

RUN apt update &&\
    apt install -y \
        virtualenv \
        python-is-python3 \
        python3 \
        python3-pip

RUN rustup install nightly
RUN cargo +nightly install cargo-criterion

COPY requirements.txt /requirements.txt
RUN pip install --break-system-packages -r /requirements.txt && rm /requirements.txt
