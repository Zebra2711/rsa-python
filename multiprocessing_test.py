import multiprocessing
import time
from multiprocessing import Pool

def cpu_bound_task(n):
    """A CPU-intensive task that computes the sum of squares up to n"""
    return sum(i * i for i in range(n))

def parallel_processing_example():
    # Get the number of CPU cores available
    num_cores = multiprocessing.cpu_count()
    print(f"Number of CPU cores available: {num_cores}")
    
    # Create a list of numbers to process
    numbers = [10000000 + x for x in range(16)]
    
    # Sequential processing
    start_time = time.time()
    sequential_result = [cpu_bound_task(n) for n in numbers]
    sequential_time = time.time() - start_time
    print(f"Sequential processing time: {sequential_time:.2f} seconds")
    
    # Parallel processing using Pool
    start_time = time.time()
    with Pool(processes=num_cores) as pool:
        parallel_result = pool.map(cpu_bound_task, numbers)
    parallel_time = time.time() - start_time
    print(f"Parallel processing time: {parallel_time:.2f} seconds")
    
    # Calculate speedup
    speedup = sequential_time / parallel_time
    print(f"Speedup: {speedup:.2f}x")

if __name__ == '__main__':
    parallel_processing_example()

# Alternative example using Process class directly
def process_example():
    def worker(number):
        """Worker function to be run in separate processes"""
        result = cpu_bound_task(number)
        print(f"Process {multiprocessing.current_process().name} computed {result}")
    
    # Create multiple processes
    processes = []
    numbers = [5000000 + x for x in range(4)]
    
    for number in numbers:
        p = multiprocessing.Process(target=worker, args=(number,))
        processes.append(p)
        p.start()
    
    # Wait for all processes to complete
    for p in processes:
        p.join()

if __name__ == '__main__':
    print("\nRunning Process example:")
    process_example()