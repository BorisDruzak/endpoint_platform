"""Expose only the bundled, payload-hashed timezone package to zipimport."""
import ast
import importlib.util
import os
import stat
import sys
import zipfile
import zipimport

if getattr(sys, 'frozen', False):
    _archive = os.path.join(sys._MEIPASS, 'tzdata-runtime.zip')
    try:
        _info = os.lstat(_archive)
        if (not stat.S_ISREG(_info.st_mode) or getattr(_info,'st_file_attributes',0) & 0x400
                or not 0 < _info.st_size <= 16*1024*1024):
            raise ValueError('invalid timezone archive')
        with zipfile.ZipFile(_archive) as _zip:
            _members = _zip.infolist()
            _names = [entry.filename for entry in _members]
            if (len(_names) != len(set(_names)) or len(_names) > 4096
                    or not {'tzdata/__init__.py','tzdata/zones'} <= set(_names)
                    or sum(entry.file_size for entry in _members) > 16*1024*1024
                    or any(not name.startswith(('tzdata/','tzdata-2026.3.dist-info/'))
                           or '..' in name.split('/') or '\\' in name or ':' in name
                           for name in _names)):
                raise ValueError('invalid timezone namespace')
            _header = _zip.read('tzdata/__init__.py')
            if len(_header) > 4096:
                raise ValueError('invalid timezone header')
            _versions = {}
            for _node in ast.parse(_header).body:
                if isinstance(_node,ast.Expr) and isinstance(_node.value,ast.Constant) and isinstance(_node.value.value,str):
                    continue
                if (isinstance(_node,ast.Assign) and len(_node.targets)==1
                        and isinstance(_node.targets[0],ast.Name) and _node.targets[0].id in {'__version__','IANA_VERSION'}
                        and isinstance(_node.value,ast.Constant) and isinstance(_node.value.value,str)
                        and _node.targets[0].id not in _versions):
                    _versions[_node.targets[0].id] = _node.value.value
                    continue
                raise ValueError('executable timezone header')
            if _versions.get('__version__') != '2026.3' or not _versions.get('IANA_VERSION'):
                raise ValueError('unexpected timezone version')
        if any(name == 'tzdata' or name.startswith('tzdata.') for name in sys.modules):
            raise ValueError('timezone package loaded before its bundled archive')
        sys.path.insert(0,_archive)
        # Resolve only: no third-party package executes before the fixed host's
        # ordinary bootstrap/extraction checks. Its eventual import uses this ZIP.
        _spec = importlib.util.find_spec('tzdata')
        if (not _spec or not isinstance(_spec.loader,zipimport.zipimporter)
                or not _spec.origin.replace('\\','/').startswith(_archive.replace('\\','/')+'/')):
            raise ValueError('unexpected timezone package origin')
        del _members, _names, _zip, _versions, _header, _node, _spec
    except Exception:
        # An uncaught runtime-hook exception in a windowed onefile helper can
        # open PyInstaller's invisible error dialog before our normal main().
        # Match the existing integrity refusal and terminate without any UI.
        if sys.stderr is not None:
            try:
                sys.stderr.write('PROVENANCE_CONFLICT\n')
                sys.stderr.flush()
            except Exception:
                pass
        os._exit(63)
