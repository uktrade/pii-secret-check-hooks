# PII (Personal Identifiable Information) and secret check hooks for pre-commit

## Installation
Install pre-commit - [Install pre-commit](https://pre-commit.com/#install)

Make sure you run:

    pre-commit install

## Setting up
 * Add a copy of `.pre-commit-config.yaml` to your repo (in the root of this repo)
 * Add a `.pii-secret-exclude` file if needed (explanation below)
 * Add a `.pii-custom-regex` file if needed (explanation below)

## Excluding files with .pii-secret-exclude
In order to exclude files from the checks add them to this file. HOWEVER, you should 
heavily favour excluding lines using `#PS-IGNORE`, rather than files.

## Adding your own regular expressions with .pii-custom-regex
Add our own regexes for secret or PII identification. Each one should be added one per line in the format:

    name=regex

Regexes used should be Python compatible and should not use start and end markers.

## Initial run
Run the following command to identify issues in your repo.

    pre-commit run --all-files

If PII or a secret is found is a false positive, add `#PS-IGNORE` (put this in a 
comment if needed) to any affected lines or, if you are certain a file can be 
excluded and will not change in the future, add it to the `.pii-secret-exclude` file.

## When committing
This logic should be run on every commit. When you find a false positive. Add 
`#PS-IGNORE` to the affected line or exclude the file (see caveats above).

Please report issues and bugs to the Live Services Team.
