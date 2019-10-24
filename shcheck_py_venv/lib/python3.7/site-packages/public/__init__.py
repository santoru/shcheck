#!/usr/bin/env python
import inspect

__all__ = ["add", "public", "test"]

"""
for frame,filename,line_number,function_name,lines,index in inspect.getouterframes()
"""


def _caller_modules():
    frames = inspect.getouterframes(inspect.currentframe())
    modules = []
    for frame, _, _, _, _, _ in frames:
        module = inspect.getmodule(frame)
        if module and module not in modules:
            modules.append(module)
    return modules


def __all__append(module, obj):
    __all__ = module.__dict__.setdefault('__all__', [])
    if obj not in __all__:  # Prevent duplicates if run from an IDE.
        __all__.append(obj)
        setattr(module, "__all__", list(sorted(__all__)))


def _isstring(value):
    try:
        int(value)
        return False
    except ValueError:
        return True
    except Exception:
        return False


def _get_key(module, obj):
    for k, v in module.__dict__.items():
        if id(v) == id(obj):
            return k


def _publish(module, obj):
    if hasattr(obj, "__name__"):  # class/function
        return __all__append(module, obj.__name__)
    # instance
    if _isstring(obj):  # string
        return __all__append(module, obj)
    key = _get_key(module, obj)  # instance
    if key:
        return __all__append(module, key)


def _add(module, objects):
    for obj in objects:
        _publish(module, obj)
    if len(objects) == 1:
        return objects[0]
    return objects


def add(*objects):
    """add objects to `__all__`"""
    return _add(_caller_modules()[1], objects)


def public(*objects):
    """add objects to `__all__`. deprecated"""
    return _add(_caller_modules()[1], objects)


def test(module):
    """test module `__all__`"""
    if not inspect.ismodule(module):
        raise ValueError("%s not a module" % module)
    for name in module.__dict__.get("__all__", []):
        if not hasattr(module, name):
            raise ValueError("'%s' not exists in %s" % (name, module))
