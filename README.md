# Blackwall

Blackwall, or **b7l**, is a partial re-implementation of [Anubis](https://anubis.techaro.lol/) in Rust.

## Usage

### Demo

Use these commands to run the demo. The difficulty level is set to 7 to provide better observability. You can tune it in `run/default.env`.

```shell
make
make www        # Start a demo web server
make www-proxy  # Start blackwall for the demo server
```

### Configuration

The configuration files are a subset of the original Anubis configuration files. They are included in `/data`.

## FAQ

To be fair these are points rather than questions.

- **Why use WebAssembly for the challenges?**
  WASM is supported by most browsers but not as much by scrapping tools. It also let's us have a single implementation of the challenge logic for both frontend and backend.

  > As of [v1.28.0](https://github.com/TecharoHQ/anubis/discussions/2014), Anubis supports WASM challenges too!

- **AI usage**
  B7L has been coded by a human (me). AI has been used to:
  - Generate HTML code
  - Generate most tests
  - Explore the original Anubis implementation in detail

- **The Long term**
  This is a sporadicly developed hobby project to learn about Anubis and practice Rust, with no future plans. Anubis remains the only real option as of writing.

## Other Blackwalls

While working on this project I saw a [reddit post](https://www.reddit.com/r/coolgithubprojects/comments/1sagnu1/the_blackwall_a_cyberpunkinspired_ebpf_firewall/) announcing [xzcrpw/blackwall](https://github.com/xzcrpw/blackwall). It's a cool project worth checking out.
