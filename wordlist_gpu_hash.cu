#include <cuda_runtime.h>

#include <cstdint>
#include <cstdio>
#include <cstring>

#if defined(_WIN32)
#define GPU_EXPORT extern "C" __declspec(dllexport)
#else
#define GPU_EXPORT extern "C" __attribute__((visibility("default")))
#endif

namespace {

unsigned char* g_data = nullptr;
std::uint64_t* g_offsets = nullptr;
std::uint32_t* g_lengths = nullptr;
std::uint64_t* g_hash_a = nullptr;
std::uint64_t* g_hash_b = nullptr;
std::size_t g_data_capacity = 0;
std::size_t g_line_capacity = 0;

void set_error(char* destination, std::size_t capacity, const char* message) {
    if (destination == nullptr || capacity == 0) {
        return;
    }
    std::snprintf(destination, capacity, "%s", message == nullptr ? "unknown CUDA error" : message);
    destination[capacity - 1] = '\0';
}

bool cuda_ok(cudaError_t result, char* error, std::size_t error_capacity) {
    if (result == cudaSuccess) {
        return true;
    }
    set_error(error, error_capacity, cudaGetErrorString(result));
    return false;
}

void free_buffers() {
    if (g_data != nullptr) {
        cudaFree(g_data);
        g_data = nullptr;
    }
    if (g_offsets != nullptr) {
        cudaFree(g_offsets);
        g_offsets = nullptr;
    }
    if (g_lengths != nullptr) {
        cudaFree(g_lengths);
        g_lengths = nullptr;
    }
    if (g_hash_a != nullptr) {
        cudaFree(g_hash_a);
        g_hash_a = nullptr;
    }
    if (g_hash_b != nullptr) {
        cudaFree(g_hash_b);
        g_hash_b = nullptr;
    }
    g_data_capacity = 0;
    g_line_capacity = 0;
}

bool reserve_buffers(
    std::size_t data_size,
    std::size_t line_count,
    char* error,
    std::size_t error_capacity
) {
    if (data_size > g_data_capacity) {
        if (g_data != nullptr) {
            cudaFree(g_data);
            g_data = nullptr;
            g_data_capacity = 0;
        }
        if (!cuda_ok(cudaMalloc(reinterpret_cast<void**>(&g_data), data_size), error, error_capacity)) {
            free_buffers();
            return false;
        }
        g_data_capacity = data_size;
    }

    if (line_count > g_line_capacity) {
        if (g_offsets != nullptr) cudaFree(g_offsets);
        if (g_lengths != nullptr) cudaFree(g_lengths);
        if (g_hash_a != nullptr) cudaFree(g_hash_a);
        if (g_hash_b != nullptr) cudaFree(g_hash_b);
        g_offsets = nullptr;
        g_lengths = nullptr;
        g_hash_a = nullptr;
        g_hash_b = nullptr;
        g_line_capacity = 0;

        const std::size_t offsets_size = line_count * sizeof(std::uint64_t);
        const std::size_t lengths_size = line_count * sizeof(std::uint32_t);
        const std::size_t hashes_size = line_count * sizeof(std::uint64_t);
        if (!cuda_ok(cudaMalloc(reinterpret_cast<void**>(&g_offsets), offsets_size), error, error_capacity) ||
            !cuda_ok(cudaMalloc(reinterpret_cast<void**>(&g_lengths), lengths_size), error, error_capacity) ||
            !cuda_ok(cudaMalloc(reinterpret_cast<void**>(&g_hash_a), hashes_size), error, error_capacity) ||
            !cuda_ok(cudaMalloc(reinterpret_cast<void**>(&g_hash_b), hashes_size), error, error_capacity)) {
            free_buffers();
            return false;
        }
        g_line_capacity = line_count;
    }
    return true;
}

__device__ __forceinline__ std::uint64_t avalanche(std::uint64_t value) {
    value ^= value >> 33;
    value *= 0xff51afd7ed558ccdULL;
    value ^= value >> 33;
    value *= 0xc4ceb9fe1a85ec53ULL;
    value ^= value >> 33;
    return value;
}

__global__ void hash_lines_kernel(
    const unsigned char* data,
    const std::uint64_t* offsets,
    const std::uint32_t* lengths,
    std::size_t line_count,
    std::uint64_t* hash_a,
    std::uint64_t* hash_b
) {
    const std::size_t index = static_cast<std::size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (index >= line_count) {
        return;
    }

    const unsigned char* line = data + offsets[index];
    const std::uint32_t length = lengths[index];

    std::uint64_t first = 14695981039346656037ULL ^ static_cast<std::uint64_t>(length);
    std::uint64_t second = 0x9e3779b97f4a7c15ULL ^ (static_cast<std::uint64_t>(length) << 32);
    for (std::uint32_t position = 0; position < length; ++position) {
        const std::uint64_t byte = line[position];
        first ^= byte;
        first *= 1099511628211ULL;

        second ^= byte + 0x9e3779b97f4a7c15ULL + (second << 6) + (second >> 2);
        second *= 0xbf58476d1ce4e5b9ULL;
    }

    hash_a[index] = avalanche(first);
    hash_b[index] = avalanche(second ^ (first + 0x94d049bb133111ebULL));
}

}  // namespace

GPU_EXPORT int gpu_info(
    int device_index,
    char* name,
    std::size_t name_capacity,
    std::uint64_t* memory_bytes,
    char* error,
    std::size_t error_capacity
) {
    int device_count = 0;
    if (!cuda_ok(cudaGetDeviceCount(&device_count), error, error_capacity)) {
        return 1;
    }
    if (device_index < 0 || device_index >= device_count) {
        set_error(error, error_capacity, "requested CUDA device does not exist");
        return 2;
    }

    cudaDeviceProp properties{};
    if (!cuda_ok(cudaGetDeviceProperties(&properties, device_index), error, error_capacity)) {
        return 3;
    }
    if (name != nullptr && name_capacity > 0) {
        std::snprintf(name, name_capacity, "%s", properties.name);
        name[name_capacity - 1] = '\0';
    }
    if (memory_bytes != nullptr) {
        *memory_bytes = static_cast<std::uint64_t>(properties.totalGlobalMem);
    }
    return 0;
}

GPU_EXPORT int gpu_hash_lines(
    int device_index,
    const unsigned char* host_data,
    std::size_t data_size,
    const std::uint64_t* host_offsets,
    const std::uint32_t* host_lengths,
    std::size_t line_count,
    std::uint64_t* host_hash_a,
    std::uint64_t* host_hash_b,
    char* error,
    std::size_t error_capacity
) {
    if (line_count == 0) {
        return 0;
    }
    if (host_data == nullptr || host_offsets == nullptr || host_lengths == nullptr ||
        host_hash_a == nullptr || host_hash_b == nullptr) {
        set_error(error, error_capacity, "invalid null pointer passed to CUDA helper");
        return 10;
    }
    if (!cuda_ok(cudaSetDevice(device_index), error, error_capacity)) {
        return 11;
    }

    const std::size_t safe_data_size = data_size == 0 ? 1 : data_size;
    if (!reserve_buffers(safe_data_size, line_count, error, error_capacity)) {
        return 12;
    }

    if (data_size > 0 && !cuda_ok(
        cudaMemcpy(g_data, host_data, data_size, cudaMemcpyHostToDevice), error, error_capacity
    )) {
        return 13;
    }
    if (!cuda_ok(cudaMemcpy(
            g_offsets, host_offsets, line_count * sizeof(std::uint64_t), cudaMemcpyHostToDevice
        ), error, error_capacity) ||
        !cuda_ok(cudaMemcpy(
            g_lengths, host_lengths, line_count * sizeof(std::uint32_t), cudaMemcpyHostToDevice
        ), error, error_capacity)) {
        return 14;
    }

    constexpr int threads = 256;
    const int blocks = static_cast<int>((line_count + threads - 1) / threads);
    hash_lines_kernel<<<blocks, threads>>>(
        g_data, g_offsets, g_lengths, line_count, g_hash_a, g_hash_b
    );
    if (!cuda_ok(cudaGetLastError(), error, error_capacity) ||
        !cuda_ok(cudaDeviceSynchronize(), error, error_capacity)) {
        return 15;
    }

    if (!cuda_ok(cudaMemcpy(
            host_hash_a, g_hash_a, line_count * sizeof(std::uint64_t), cudaMemcpyDeviceToHost
        ), error, error_capacity) ||
        !cuda_ok(cudaMemcpy(
            host_hash_b, g_hash_b, line_count * sizeof(std::uint64_t), cudaMemcpyDeviceToHost
        ), error, error_capacity)) {
        return 16;
    }
    return 0;
}

GPU_EXPORT void gpu_release() {
    free_buffers();
}
