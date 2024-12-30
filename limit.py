import resource
import platform
import sys

def memory_limit_kb(limit_kb: int):
    """
    Sets the memory limit in KB for the current process on Linux.

    Args:
        limit_kb: The memory limit in KB.
    """
    if platform.system() != "Linux":
        print('Only works on Linux!')
        return

    # Convert limit_mb to bytes
    limit_bytes = limit_kb * 1024

    soft, hard = resource.getrlimit(resource.RLIMIT_AS)
    resource.setrlimit(resource.RLIMIT_AS, (limit_bytes, hard))

def memory(limit_kb: int):
    """
    Decorator to limit memory usage for the decorated function.

    Args:
        limit_mb: The memory limit in KB.

    Raises:
        MemoryError: If the memory limit is exceeded.
    """
    def decorator(function):
        def wrapper(*args, **kwargs):
            memory_limit_kb(limit_kb)
            try:
                print(f"Memory limit: {limit_kb} KB")
                return function(*args, **kwargs)
            except MemoryError:
                print(f"Memory limit of {limit_kb} KB exceeded.")
                sys.exit(1)
        return wrapper
    return decorator


