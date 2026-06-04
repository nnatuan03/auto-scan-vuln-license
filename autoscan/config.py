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
    "gradle": ("build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts", "gradlew", "gradlew.bat"),
    "node": ("package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb"),
    "flutter": ("pubspec.yaml",),
    "dotnet": (".sln", ".csproj"),
    "python": ("requirements.txt", "pyproject.toml", "Pipfile", "poetry.lock"),
    "go": ("go.mod",),
    "php": ("composer.json", "composer.lock"),
    "ruby": ("Gemfile", "Gemfile.lock"),
}
