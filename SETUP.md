# Setup

## Create and activate a virtual environment
```
python -m venv .venv
.\\.venv\\Scripts\\activate
```

## Install
```
pip install -r requirements.txt
pip install -e .
```

## Run
```
docseal --help
docseal encrypt path\\to\\image.png
docseal decrypt path\\to\\image.png.imgenc
```

## Tests
```
pytest
```