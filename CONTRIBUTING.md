# Contributing to varwof-engine

Thank you for considering contributing to varwof-engine!

## How to contribute

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/amazing`)
3. Make your changes
4. Run tests: `go test -count=1 ./...`
5. Commit with a clear message (`git commit -m "feat: add amazing feature"`)
6. Push and open a Pull Request

## Code style

- Follow standard Go formatting (`gofmt -s`)
- Run `go vet ./...` before committing
- All exported types/functions must have doc comments
- Keep functions small and focused

## Commit convention

We use [Conventional Commits](https://www.conventionalcommits.org/):

| Type       | Usage                    |
|------------|--------------------------|
| `feat:`    | New feature              |
| `fix:`     | Bug fix                  |
| `docs:`    | Documentation changes    |
| `refactor:`| Code restructuring      |
| `test:`    | Adding/modifying tests   |
| `chore:`   | Build/config/tooling     |

## Testing

- All tests must pass: `go test -count=1 ./...`
- Dialect tests cover SQLite / PostgreSQL / MySQL backends

## Contributor License Agreement

By submitting a pull request, you agree to sign the
[Individual CLA](https://github.com/varwof/.github/blob/main/CLA-INDIVIDUAL.md)
(or [Corporate CLA](https://github.com/varwof/.github/blob/main/CLA-CORPORATE.md)
for employer-sponsored contributions). The CLA Assistant bot will prompt
you to sign when you open your first pull request; signing once covers all
Varwof repositories.

By contributing, you agree that your contributions are licensed under the
AGPL-3.0 license, as described in [LICENSE](LICENSE).
