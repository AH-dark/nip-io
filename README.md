# NS IP

This is a toy project that built a simple dynamic domain dns server that can be used to resolve domain names to IP
addresses. The server is built using Rust and the trust-dns library.

## Features

- [x] Resolve domain names like `app.1.2.3.4.ip.local` to `1.2.3.4`
- [x] Resolve domain names like `app-1-2-3-4.ip.local` to `1.2.3.4`
- [x] Resolve domain names like `4-3-2-1-app.ip.local` to `1.2.3.4`
- [x] Resolve domain names like `a.b.c.1-2-3-4.ip.local` to `1.2.3.4`
- [ ] Resolve IPv6 domain names
- [ ] Auto response CNAME records
- [ ] More localhost domain names support

## Usage

1. Clone the repository
2. Fill or change the `.env` file
3. Run the server using `cargo run`

## License

This project is licensed under the GNU Affero General Public License v3.0 - see the [LICENSE](LICENSE) file for details.
