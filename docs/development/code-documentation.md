# Code Documentation Guide

## Python Docstrings (Google Style)

### Module Documentation

```python
"""Module-level docstring.

This module provides functionality for X, Y, and Z.
It's designed to be used in conjunction with module A and B.

Example:
    Basic usage of this module::

        from mypackage import mymodule
        result = mymodule.do_something()

Attributes:
    module_variable (str): Description of module variable.

Todo:
    * Add support for feature X
    * Optimize performance of Y
"""
```

### Class Documentation

```python
class DocumentProcessor:
    """Process various document types for vector storage.

    This class handles the processing of different document formats
    (PDF, DOCX, TXT) and prepares them for storage in a vector database.

    Attributes:
        vector_store: The vector storage backend.
        chunk_size: Maximum size of text chunks in tokens.
        overlap: Number of overlapping tokens between chunks.

    Example:
        >>> processor = DocumentProcessor(vector_store)
        >>> chunks = await processor.process_file("document.pdf")
        >>> print(f"Processed {len(chunks)} chunks")

    Note:
        Large files may take significant time to process.
        Consider using batch processing for multiple files.
    """
```

### Function Documentation

```python
async def process_file(
    self,
    file_path: str,
    metadata: Optional[Dict[str, Any]] = None,
    *,
    extract_images: bool = False
) -> List[Document]:
    """Process a single file into document chunks.

    This method reads the file, extracts text content, splits it into
    chunks, and generates embeddings for each chunk.

    Args:
        file_path: Path to the file to process.
        metadata: Additional metadata to attach to chunks.
        extract_images: Whether to extract and process images.

    Returns:
        List of processed document chunks with embeddings.

    Raises:
        FileNotFoundError: If the file doesn't exist.
        ValueError: If file type is not supported.
        ProcessingError: If processing fails.

    Example:
        >>> chunks = await processor.process_file(
        ...     "report.pdf",
        ...     metadata={"department": "engineering"},
        ...     extract_images=True
        ... )
    """
```

## Type Hints Best Practices

### Basic Types

```python
from typing import Optional, Union, List, Dict, Set, Tuple, Any
from datetime import datetime
from pathlib import Path

# Type aliases for clarity
UserId = str
DocumentId = str
EmbeddingVector = List[float]
```

### Advanced Types

```python
from typing import TypeVar, Generic, Protocol, Literal, TypedDict

# Type variables
T = TypeVar('T')
TDocument = TypeVar('TDocument', bound='BaseDocument')

# Literal types
ModelType = Literal["gpt-4", "claude-3", "llama-2"]
Status = Literal["pending", "processing", "completed", "failed"]

# TypedDict for structured dicts
class DocumentMetadata(TypedDict, total=False):
    title: str
    author: str
    created_date: datetime
    tags: List[str]

# Protocol for duck typing
class Embeddable(Protocol):
    def to_text(self) -> str: ...
    @property
    def metadata(self) -> Dict[str, Any]: ...
```

## Documentation Tools

### Generating Documentation

```bash
# Generate API documentation
python -m sphinx.apidoc -o docs/api src/

# Generate HTML documentation
sphinx-build -b html docs/ docs/_build/

# Check docstring coverage
pydocstyle src/ --convention=google
```

### VS Code Extensions

- Python Docstring Generator
- autoDocstring
- Better Comments

### Pre-commit Hooks

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/pycqa/pydocstyle
    rev: 6.3.0
    hooks:
      - id: pydocstyle
        args: [--convention=google]
```