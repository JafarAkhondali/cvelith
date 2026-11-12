import subprocess
import tempfile
import shutil


def clone_repository(repo_url: str) -> str:
    """
    Clone repository to a temporary directory.

    Args:
        repo_url: URL of the Metasploit repository

    Returns:
        Path to the cloned repository

    Raises:
        RuntimeError: If cloning fails
    """
    temp_dir = tempfile.mkdtemp()
    try:
        subprocess.run(
            ['git', 'clone', '--depth', '1', repo_url, temp_dir],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        return temp_dir
    except subprocess.CalledProcessError as e:
        shutil.rmtree(temp_dir)
        raise RuntimeError(f"Error cloning repository: {e}")
