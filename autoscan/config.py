from __future__ import annotations

DEFAULT_RESULTS_DIR = "scan-results"
DEFAULT_MAX_WORKERS = 4
DEFAULT_RECURSIVE_DEPTH = 5

IGNORE_DIR_NAMES = {
    ".git",
    ".hg",
    ".svn",
    ".idea",
    ".vscode",
    "__pycache__",
    "node_modules",
    ".pnpm-store",
    ".gradle",
    "target",
    "build",
    "dist",
    "out",
    "bin",
    "obj",
    "coverage",
    ".next",
    ".nuxt",
    ".terraform",
    DEFAULT_RESULTS_DIR,
}

PROJECT_MARKERS: dict[str, tuple[str, ...]] = {
    "maven": ("pom.xml",),
    "gradle": ("build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts", "gradle.lockfile", "gradlew", "gradlew.bat"),
    "node": ("package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb"),
    "flutter": ("pubspec.yaml",),
    "dotnet": (".sln", ".csproj", ".fsproj", ".vbproj", ".xsproj", "packages.lock.json", "packages.config", "project.assets.json", "Directory.Packages.props"),
    "python": ("requirements.txt", "pyproject.toml", "Pipfile", "Pipfile.lock", "poetry.lock", "uv.lock", "requirements.lock", "conda-lock.yml", "conda-lock.yaml"),
    "go": ("go.mod", "go.sum"),
    "rust": ("Cargo.toml", "Cargo.lock"),
    "php": ("composer.json", "composer.lock"),
    "ruby": ("Gemfile", "Gemfile.lock"),
    "swift": ("Package.swift", "Package.resolved"),
    "cocoapods": ("Podfile", "Podfile.lock"),
    "elixir": ("mix.exs", "mix.lock"),
    "erlang": ("rebar.config", "rebar.lock"),
    "java": ("*.jar", "*.war", "*.ear", "*.par", "sbt.lock"),
    "conda": ("environment.yml", "environment.yaml", "conda-lock.yml", "conda-lock.yaml"),
    "julia": ("Project.toml", "Manifest.toml"),
    "r": ("renv.lock", "pak.lock", "DESCRIPTION"),
    "cpp": ("conan.lock", "conanfile.txt", "conanfile.py", "vcpkg.json", "vcpkg-lock.json"),
    "iac": ("Dockerfile", "Containerfile", "docker-compose.yml", "docker-compose.yaml", "Chart.yaml", "Chart.lock", "kustomization.yaml", "main.tf", "terraform.lock.hcl", ".terraform.lock.hcl", "serverless.yml", "serverless.yaml"),
}
