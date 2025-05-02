import datetime
import pathlib
import sys
from enum import StrEnum, auto
from uuid import UUID

from pydantic import BaseModel, Field, HttpUrl


class Environment(StrEnum):
    attack_range = auto()


class AttackDataYml(BaseModel):
    author: str = Field(..., min_length=5)
    id: UUID
    date: datetime.date
    description: str = Field(..., min_length=5)
    environment: Environment
    dataset: list[HttpUrl] = Field(..., min_length=1)
    sourcetypes: list[str] = Field(..., min_length=1)
    references: list[HttpUrl] = Field(..., min_length=1)


# Get all of the yml files in the datasets folder
datasets_root = pathlib.Path("datasets/")


# We only permit certain filetypes to be present in this directory.
# This is to avoid the inclusion of unsupported file types and to
# assist in the validation of the YML files
ALLOWED_SUFFIXES = [".yml", ".log", ".json"]
SPECIAL_GIT_GILES = ".gitkeep"
bad_files = [
    name
    for name in datasets_root.glob(r"**/*.*")
    if name.is_file()
    and not (name.suffix in ALLOWED_SUFFIXES or name.name == SPECIAL_GIT_GILES)
]

if len(bad_files) > 0:
    print(
        f"Error, the following files were found in the {datasets_root} folder.  Only files ending in {ALLOWED_SUFFIXES} or {SPECIAL_GIT_GILES} are allowed:"
    )
    print("\n".join([str(f) for f in bad_files]))
    sys.exit(1)
