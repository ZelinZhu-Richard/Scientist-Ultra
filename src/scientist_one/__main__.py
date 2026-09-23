"""Fail-closed legacy entry point; use the captured-source launcher."""


def main() -> int:
    print(
        '{"error_type":"UnsafeStartupError",'
        '"message":"refusing unisolated startup; use the verified '
        'python3 -I -S -B scripts/scientist_one_cli.py launcher",'
        '"status":"ERROR"}'
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
