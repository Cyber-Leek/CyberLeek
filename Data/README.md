# Network Flow Data

This folder is intended for datasets used by the Network IDS.

## Dataset Types

Examples include:

- Training data
- Testing data
- Sample network flows
- Evaluation datasets

## Expected ML Format

The machine-learning dataset contains network-flow features and a `Label`
column.

Label values:

- `0` = BENIGN
- `1` = ATTACK

The production repository does not store large datasets directly because
dataset files can be very large.

Large datasets should be downloaded separately or provided through the project
documentation.