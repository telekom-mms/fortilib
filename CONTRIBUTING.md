## Local Development and testing

We accept all kinds of contributions, whether they are bug fixes, pull requests or documentation updates!

Setting up the local enviroment is done with [python poetry](https://python-poetry.org/)

```
> poetry install
```

### Linting with tox

After making code changes, please run the linters and fix all errors:

```
> poetry run tox -elinter
```

### Auto formatting code

After making code changes, please run code formatters:

```
> poetry run tox -eformatter
```


### Running tests

We require unit tests for all code changes.

Run tests:

```
> poetry run tox
```
