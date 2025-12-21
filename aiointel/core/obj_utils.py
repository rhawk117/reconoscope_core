from __future__ import annotations

import dataclasses as dc
from typing import TYPE_CHECKING, Any

import msgspec

if TYPE_CHECKING:
    from collections.abc import Iterable

class UnsupportedObjectTypeError(TypeError):
    supported_calling_codes = (
        "msgspec.Struct",
        "dataclass",
        "class with __dict__",
        "class with __slots__",
    )

    def __init__(
        self,
        use_case: str,
        only_supported: Iterable[str] | None = None,
    ) -> None:
        if only_supported is not None:
            self.supported_calling_codes = tuple(only_supported)
        message = (
            f"Unsupported object type for {use_case}. "
            f"Supported types are: {', '.join(self.supported_calling_codes)}."
        )
        super().__init__(message)


type FieldTypes = msgspec.structs.FieldInfo | dc.Field

def supports_fields(obj: Any) -> bool:
    """
    Check if an object supports fields (i.e., is a ``msgspec.Struct`` or a
    ``dataclass``).

    Parameters
    ----------
    obj : Any
        The object to check.

    Returns
    -------
    bool
        ``True`` if the object supports fields, ``False`` otherwise.
    """
    return isinstance(obj, msgspec.Struct) or dc.is_dataclass(obj)


def get_object_fields(obj: Any) -> Iterable[FieldTypes]:
    """
    Get the fields of an object; raises ``UnsupportedObjectTypeError`` if the object
    is not supported. Supported types are ``msgspec.Struct`` and ``dataclass``.

    Parameters
    ----------
    obj : Any
        The object to get the fields from.

    Returns
    -------
    Iterable[FieldTypes]
        An iterable of the object's fields.

    Raises
    ------
    UnsupportedObjectTypeError
        If the object type is not supported.
    """
    if isinstance(obj, msgspec.Struct):
        return msgspec.structs.fields(type(obj))

    if dc.is_dataclass(obj):
        return dc.fields(obj)

    raise UnsupportedObjectTypeError(
        use_case="get_object_fields",
        only_supported=("msgspec.Struct", "dataclass"),
    )

def get_object_field_names(obj: Any) -> Iterable[str]:
    """
    Get the field names of an object.

    Parameters
    ----------
    obj : Any
        The object to get the field names from.

    Returns
    -------
    Iterable[str]
        An iterable of the object's field names.
    """
    return (field.name for field in get_object_fields(obj))


def copy_object[T](object_instance: T, **overrides: Any) -> T:
    """
    Create a copy of an object, optionally overriding some fields.


    Returns
    -------
    T
        A copy of the object with the specified overrides.
    **overrides : Any
        Fields to override in the copied object.

    Raises
    ------
    UnsupportedObjectTypeError
        If the object type is not supported.
    """
    obj_type = type(object_instance)
    if isinstance(object_instance, msgspec.Struct):
        return msgspec.structs.replace(object_instance, **overrides)

    if dc.is_dataclass(object_instance):
        return dc.replace(object_instance, **overrides)  # type: ignore[return-value]

    if obj_dict := getattr(object_instance, "__dict__", None):
        init_values = obj_dict.copy()
        if overrides:
            init_values.update(overrides)

        return obj_type(**init_values)

    if slots := getattr(obj_type, "__slots__", ()):
        init_values = {slot: getattr(object_instance, slot) for slot in slots}
        if overrides:
            init_values.update(overrides)

        return obj_type(**init_values)

    raise UnsupportedObjectTypeError("copy_object")

def object_as_dict(obj: Any) -> dict[str, Any]:
    if isinstance(obj, msgspec.Struct):
        return msgspec.structs.asdict(obj)

    if dc.is_dataclass(obj):
        return dc.asdict(obj) # type: ignore[return-value]

    if obj_dict := getattr(obj, "__dict__", None):
        return obj_dict.copy()

    if slots := getattr(type(obj), "__slots__", ()):
        return {slot: getattr(obj, slot) for slot in slots}

    raise UnsupportedObjectTypeError("object_as_dict")
