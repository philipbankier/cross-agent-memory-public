"""Setuptools hooks: stamp outputs only after checking the complete build inputs."""

import runpy
from pathlib import Path

from setuptools.command.bdist_wheel import bdist_wheel
from setuptools.command.build_py import build_py
from setuptools.command.egg_info import egg_info
from setuptools.command.sdist import sdist

ROOT = Path(__file__).resolve().parent
PROVENANCE = runpy.run_path(str(ROOT / "src/cross_assistant_memory/runtime_provenance.py"))


def require_empty_directory(path):
    if path.is_symlink() or (path.exists() and (not path.is_dir() or any(path.iterdir()))):
        raise RuntimeError("package staging must be a fresh directory")


class VerifiedEggInfo(egg_info):
    def run(self):
        path = Path(self.egg_info)
        PROVENANCE["verify_metadata_directory"](path, PROVENANCE["EGG_INFO_FILES"])
        super().run()
        PROVENANCE["verify_metadata_directory"](path, PROVENANCE["EGG_INFO_FILES"])


class VerifiedBdistWheel(bdist_wheel):
    def run(self):
        if self.skip_build:
            raise RuntimeError("skip-build bypasses verified package construction")
        require_empty_directory(Path(self.bdist_dir))
        if self.dist_info_dir:
            # PEP 517 permits prepared metadata, but it must match this verified build.
            PROVENANCE["source_provenance"](ROOT)
            metadata = Path(self.dist_info_dir)
            names = {
                "METADATA": "PKG-INFO",
                "entry_points.txt": "entry_points.txt",
                "top_level.txt": "top_level.txt",
            }
            PROVENANCE["verify_metadata_directory"](
                metadata, frozenset((*names, "licenses/LICENSE"))
            )
            self.run_command("egg_info")
            generated = Path(self.get_finalized_command("egg_info").egg_info)
            expected = {
                name: (generated / source).read_bytes()
                for name, source in names.items()
                if (generated / source).is_file()
            }
            expected["licenses/LICENSE"] = (ROOT / "LICENSE").read_bytes()
            actual = {
                item.relative_to(metadata).as_posix(): item.read_bytes()
                for item in metadata.rglob("*")
                if item.is_file()
            }
            if actual != expected:
                raise RuntimeError("prepared metadata differs from verified build inputs")
        super().run()


class VerifiedBuildPy(build_py):
    def run(self):
        if self.editable_mode:
            return super().run()
        provenance = PROVENANCE["source_provenance"](ROOT)
        super().run()
        build_root = Path(self.build_lib)
        if any(path.name != "cross_assistant_memory" for path in build_root.iterdir()):
            raise RuntimeError("unexpected package in build output")
        package = build_root / "cross_assistant_memory"
        if any(path.suffix == ".pyc" for path in package.rglob("*")):
            raise RuntimeError("build output contains bytecode")
        PROVENANCE["verify_package"](package, provenance)
        # build_py may have copied the sdist's stamp. Replace only this generated output.
        (package / PROVENANCE["MANIFEST"]).unlink(missing_ok=True)
        PROVENANCE["write_manifest"](package, provenance)


class VerifiedSdist(sdist):
    def make_release_tree(self, base_dir, files):
        provenance = PROVENANCE["source_provenance"](ROOT)
        require_empty_directory(Path(base_dir))
        selected = set(provenance["build_inputs"])
        selected.update(
            f"src/cross_assistant_memory/{name}" for name in provenance["package_files"]
        )
        super().make_release_tree(base_dir, sorted(selected))
        # This static pyproject build does not use setuptools' generated egg_info overrides.
        (Path(base_dir) / "setup.cfg").unlink(missing_ok=True)
        package = Path(base_dir) / "src/cross_assistant_memory"
        (package / PROVENANCE["MANIFEST"]).unlink(missing_ok=True)
        PROVENANCE["write_manifest"](package, provenance)
