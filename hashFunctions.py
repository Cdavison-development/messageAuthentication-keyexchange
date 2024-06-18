import hashlib
import itertools
import string
import timeit
import random


def generate_hash(input_data):
    # Generate SHA-256 hash
    return hashlib.sha256(input_data.encode()).hexdigest()

def measure_execution_time(data_size, number_of_executions=1000):
    # Generate random data of specified size
    random_data = ''.join(random.choices(string.ascii_letters + string.digits, k=data_size))
    
    # Measure the time taken to compute the hash
    execution_time = timeit.timeit(lambda: generate_hash(random_data), number=number_of_executions)
    return execution_time

# Testing with different sizes of data
data_sizes = [10, 100, 1000, 10000]
for size in data_sizes:
    time_taken = measure_execution_time(size)
    print(f"Time taken to compute hash of data size {size}: {time_taken:.6f} seconds")
    print("\n")

def brute_force_attack(target_hash, max_length=4):
    # Define a simple character set to generate potential inputs.
    chars = 'abcdefghijklmnopqrstuvwxyz0123456789'

    def generate_inputs(current):
        if len(current) == max_length:
            return
        for char in chars:
            new_input = current + char
            if hashlib.sha256(new_input.encode()).hexdigest() == target_hash:
                return new_input
            else:
                found_input = generate_inputs(new_input)
                if found_input:
                    return found_input
        return None

    return generate_inputs('')

# Example usage
target_input = 'test'
target_hash = hashlib.sha256(target_input.encode()).hexdigest()
found_input = brute_force_attack(target_hash)

if found_input:
    print(f"Input '{found_input}' hashes to the target hash. \n")
else:
    print("No match found within the given constraints.")

# Example of data confidentiality and consistent output
original_data = "secret"
hashed_data = generate_hash(original_data)
print(f"Original Data: {original_data}")
print(f"Hashed Data: {hashed_data}")


# Consistency demonstration
print("\nConsistency demonstration:")
print(f"Hash of 'secret': {generate_hash('secret')}")
print(f"Hash of 'secret' again: {generate_hash('secret')}")
