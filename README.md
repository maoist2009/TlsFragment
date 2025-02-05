# About

Two ways to protect your TLS connection with out decryption. 

# Usage

All the config is in `config.json`.

## Domain match

We use an AC automaton to match the domains.

We map the **longest** domain setting for the sni. If multiple, randomly choose one of **the longests**. (You'll see the code, it determines the python `sorted` function).

## [HELP](./docs/HELP.md)
