#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "mpi.h"

#define ROTR(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define SHR(x, n) ((x) >> (n))

#define Ch(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define BSIG0(x) (ROTR(x, 28) ^ ROTR(x, 34) ^ ROTR(x, 39))
#define BSIG1(x) (ROTR(x, 14) ^ ROTR(x, 18) ^ ROTR(x, 41))
#define SSIG0(x) (ROTR(x, 1) ^ ROTR(x, 8) ^ SHR(x, 7))
#define SSIG1(x) (ROTR(x, 19) ^ ROTR(x, 61) ^ SHR(x, 6))

#define MPI_ASK_FOR_TASK 1
#define MPI_KILL_WORKER 2

#define MAX_HASHES 1056
#define MAX_WORD_LEN 16

// int contaTeste = 0;
/* caracteres permitidos */
const char charset[] = "abcdefghijklmnopqrstuvwxyz";

int charset_len;

/* alvo */
uint8_t target[64];

typedef struct
{
    uint64_t state[8];
    uint64_t bitlen;
    uint8_t buffer[128];
    size_t buffer_len;
} SHA512_CTX;

static const uint64_t K[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL};

void sha512_transform(SHA512_CTX *ctx, const uint8_t data[])
{
    uint64_t m[80], a, b, c, d, e, f, g, h, t1, t2;
    int i, j;

    for (i = 0, j = 0; i < 16; ++i, j += 8)
        m[i] = ((uint64_t)data[j] << 56) | ((uint64_t)data[j + 1] << 48) |
               ((uint64_t)data[j + 2] << 40) | ((uint64_t)data[j + 3] << 32) |
               ((uint64_t)data[j + 4] << 24) | ((uint64_t)data[j + 5] << 16) |
               ((uint64_t)data[j + 6] << 8) | ((uint64_t)data[j + 7]);
    for (; i < 80; ++i)
        m[i] = SSIG1(m[i - 2]) + m[i - 7] + SSIG0(m[i - 15]) + m[i - 16];

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (i = 0; i < 80; ++i)
    {
        t1 = h + BSIG1(e) + Ch(e, f, g) + K[i] + m[i];
        t2 = BSIG0(a) + Maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

void sha512_init(SHA512_CTX *ctx)
{
    ctx->state[0] = 0x6a09e667f3bcc908ULL;
    ctx->state[1] = 0xbb67ae8584caa73bULL;
    ctx->state[2] = 0x3c6ef372fe94f82bULL;
    ctx->state[3] = 0xa54ff53a5f1d36f1ULL;
    ctx->state[4] = 0x510e527fade682d1ULL;
    ctx->state[5] = 0x9b05688c2b3e6c1fULL;
    ctx->state[6] = 0x1f83d9abfb41bd6bULL;
    ctx->state[7] = 0x5be0cd19137e2179ULL;
    ctx->bitlen = 0;
    ctx->buffer_len = 0;
}

void sha512_update(SHA512_CTX *ctx, const uint8_t data[], size_t len)
{
    size_t i;

    for (i = 0; i < len; ++i)
    {
        ctx->buffer[ctx->buffer_len++] = data[i];
        if (ctx->buffer_len == 128)
        {
            sha512_transform(ctx, ctx->buffer);
            ctx->bitlen += 1024;
            ctx->buffer_len = 0;
        }
    }
}

void sha512_final(SHA512_CTX *ctx, uint8_t hash[])
{
    size_t i = ctx->buffer_len;
    uint64_t bitlen = ctx->bitlen + i * 8;

    ctx->buffer[i++] = 0x80;
    if (i > 112)
    {
        while (i < 128)
            ctx->buffer[i++] = 0x00;
        sha512_transform(ctx, ctx->buffer);
        i = 0;
    }
    while (i < 112)
        ctx->buffer[i++] = 0x00;

    for (int j = 15; j >= 0; --j)
    {
        ctx->buffer[112 + j] = (uint8_t)(bitlen & 0xff);
        bitlen >>= 8;
    }

    sha512_transform(ctx, ctx->buffer);

    for (i = 0; i < 8; ++i)
    {
        hash[i * 8] = (ctx->state[i] >> 56) & 0xff;
        hash[i * 8 + 1] = (ctx->state[i] >> 48) & 0xff;
        hash[i * 8 + 2] = (ctx->state[i] >> 40) & 0xff;
        hash[i * 8 + 3] = (ctx->state[i] >> 32) & 0xff;
        hash[i * 8 + 4] = (ctx->state[i] >> 24) & 0xff;
        hash[i * 8 + 5] = (ctx->state[i] >> 16) & 0xff;
        hash[i * 8 + 6] = (ctx->state[i] >> 8) & 0xff;
        hash[i * 8 + 7] = ctx->state[i] & 0xff;
    }
}


// -------------------------------

void print_hash_hex(const uint8_t hash[64])
{
    for (int i = 0; i < 64; ++i)
        printf("%02x", hash[i]);
    printf("\n");
}
void sha512_string(const char *msg, uint8_t hash[64])
{
    SHA512_CTX ctx;
    sha512_init(&ctx);
    sha512_update(&ctx, (const uint8_t *)msg, strlen(msg));
    sha512_final(&ctx, hash);
}

int brute(char *buffer, int depth, int maxDepth)
{
    if (depth == maxDepth)
    {
        buffer[depth] = '\0';
        uint8_t hash[64];
        sha512_string(buffer, hash);
        if (memcmp(hash, target, 64) == 0)
        {
            return 1; // encontrou
        }
        return 0;
    }

    for (int i = 0; i < charset_len; ++i)
    {
        buffer[depth] = charset[i];
        if (brute(buffer, depth + 1, maxDepth))
            return 1; // interrompe recursão ao encontrar
    }

    return 0;
}


void generate_and_test(int length)
{
    char buffer[length + 1];
    buffer[length] = '\0';

    uint64_t total = 1;
    for (int i = 0; i < length; ++i)
        total *= charset_len;

    for (uint64_t n = 0; n < total; ++n)
    {
        uint64_t x = n;
        for (int pos = length - 1; pos >= 0; --pos)
        {
            buffer[pos] = charset[x % charset_len];
            x /= charset_len;
        }

        uint8_t hash[64];
        sha512_string(buffer, hash);
        if (memcmp(hash, target, 64) == 0)
        {
            return;
        }
    }
}

/*
    TODO:
    - enviar para o trabalhador o hash a ser quebrado e o tamanho da palavra alvo
    - TRABALHADOR DEVE PEDIR TRABALHO AO COORDENADOR
*/


int main(int argc, char *argv[])
{
    int my_rank, proc_n;
    MPI_Status status;

    MPI_Init(&argc, &argv);
    MPI_Comm_rank(MPI_COMM_WORLD, &my_rank);
    MPI_Comm_size(MPI_COMM_WORLD, &proc_n);

    charset_len = strlen(charset);

    // ==========================
    //     MODO SEQUENCIAL
    // ==========================
    if (proc_n == 1)
    {
        double start_time, end_time;
        start_time = MPI_Wtime();

        FILE *hf = fopen("hash.txt", "r");
        FILE *tf = fopen("texto.txt", "r");
        if (!hf || !tf)
        {
            fprintf(stderr, "Erro: nao foi possivel abrir hash.txt ou texto.txt\n");
            MPI_Finalize();
            return 1;
        }

        uint8_t target_local[64];
        char hash_line[256];
        char word_line[256];

        while (fgets(hash_line, sizeof(hash_line), hf) && fgets(word_line, sizeof(word_line), tf))
        {
            word_line[strcspn(word_line, "\r\n")] = '\0';

            // converte hash hex -> bytes
            for (int k = 0; k < 64; ++k)
                sscanf(hash_line + k * 2, "%2hhx", &target_local[k]);

            memcpy(target, target_local, 64);
            int maxLen = strlen(word_line);

            double start = MPI_Wtime();
            int found = 0;
            for (int i = 0; i < charset_len && !found; ++i)
            {
                char localBuffer[MAX_WORD_LEN];
                localBuffer[0] = charset[i];
                if (brute(localBuffer, 1, maxLen))
                    found = 1;
            }
            double end = MPI_Wtime();

            if (!found)
                printf("[SEQ] Nada encontrado <%s> -> %f segundos.\n", word_line, end - start);
            // printf("[SEQ] Palavra <%s> encontrada em %f segundos!\n", word_line, end - start);
        }

        fclose(hf);
        fclose(tf);
        end_time = MPI_Wtime();
        printf("[FINAL] Tempo total de execucao: %3.2f segundos\n", end_time - start_time);
        MPI_Finalize();
        return 0;
    }

    // ==========================
    //     MODO MPI
    // ==========================

    if (my_rank == 0)
    { // ------------------ COORDENADOR ------------------
        double coord_start_time, coord_stop_time;
        coord_start_time = MPI_Wtime();

        FILE *hf = fopen("hash.txt", "r");
        FILE *tf = fopen("texto.txt", "r");
        if (!hf || !tf)
        {
            fprintf(stderr, "Erro: nao foi possivel abrir hash.txt ou texto.txt\n");
            MPI_Abort(MPI_COMM_WORLD, 1);
        }

        uint8_t target_list[MAX_HASHES][64];
        char word_list[MAX_HASHES][MAX_WORD_LEN];
        int num_hashes = 0;

        char hash_line[256];
        char word_line[256];

        while (fgets(hash_line, sizeof(hash_line), hf) && fgets(word_line, sizeof(word_line), tf))
        {
            // limpar newline
            word_line[strcspn(word_line, "\r\n")] = '\0';

            // extrair apenas hex válidos
            char hexbuf[129];
            int j = 0;
            for (int i = 0; hash_line[i] && j < 128; ++i)
            {
                char c = hash_line[i];
                if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))
                    hexbuf[j++] = c;
            }
            hexbuf[j] = '\0';

            if (j != 128)
            {
                fprintf(stderr, "Ignorando linha %d: hash inválido (%d chars)\n", num_hashes + 1, j);
                continue;
            }

            for (int k = 0; k < 64; ++k)
                sscanf(hexbuf + k * 2, "%2hhx", &target_list[num_hashes][k]);

            strncpy(word_list[num_hashes], word_line, MAX_WORD_LEN - 1);
            word_list[num_hashes][MAX_WORD_LEN - 1] = '\0';

            num_hashes++;
            if (num_hashes >= MAX_HASHES)
                break;
        }

        fclose(hf);
        fclose(tf);

        if (num_hashes == 0)
        {
            fprintf(stderr, "Nenhum par hash/palavra válido encontrado.\n");
            MPI_Abort(MPI_COMM_WORLD, 1);
        }


        // --- distribuição de tarefas ---
        int next_hash = 0;
        int active_workers = proc_n - 1;

        while (active_workers > 0)
        {
            MPI_Recv(NULL, 0, MPI_CHAR, MPI_ANY_SOURCE, MPI_ASK_FOR_TASK, MPI_COMM_WORLD, &status);
            int worker = status.MPI_SOURCE;
            //printf("[Master - C%d] Recebeu pedido de tarefa do worker %d (total pedidos)", contaTeste++, worker);

            if (next_hash < num_hashes)
            {
                struct
                {
                    uint8_t hash[64];
                    char word[MAX_WORD_LEN];
                } task_data;

                memcpy(task_data.hash, target_list[next_hash], 64);
                strncpy(task_data.word, word_list[next_hash], MAX_WORD_LEN);

                MPI_Send(&task_data, sizeof(task_data), MPI_BYTE, worker, 0, MPI_COMM_WORLD);

                // printf("[Master] Enviando tarefa %d (%s) para worker %d\n",
                    //    next_hash + 1, word_list[next_hash], worker);

                next_hash++;
            }
            else
            {
                MPI_Send(NULL, 0, MPI_CHAR, worker, MPI_KILL_WORKER, MPI_COMM_WORLD);
                active_workers--;
            }
        }

        coord_stop_time = MPI_Wtime();
        printf("[Final] Tempo total de execucao do coordenador: %3.2f segundos\n", coord_stop_time - coord_start_time);
    }
    else
    { // ------------------ WORKER ------------------
        while (1)
        {
            double local_worker_start_time, local_worker_stop_time = 0.0;
            local_worker_start_time = MPI_Wtime();

            // pede tarefa
            MPI_Send(NULL, 0, MPI_CHAR, 0, MPI_ASK_FOR_TASK, MPI_COMM_WORLD);
            // printf("[Worker %d - C%d] Pedido de tarefa enviado \n", my_rank, contaTeste++);
            struct
            {
                uint8_t hash[64];
                char word[MAX_WORD_LEN];
            } task_data;

            MPI_Recv(&task_data, sizeof(task_data), MPI_BYTE, 0, MPI_ANY_TAG, MPI_COMM_WORLD, &status);

            if (status.MPI_TAG == MPI_KILL_WORKER)
                break;

            memcpy(target, task_data.hash, 64);

            int maxLen = strlen(task_data.word);

            // printf("[Worker %d] Recebeu tarefa com alvo \"%s\" (len=%d)\n",
                //    my_rank, task_data.word, maxLen);

            // faz brute force para esse alvo
            int local_found = 0;
            for (int i = 0; i < charset_len && !local_found; ++i)
            {
                char localBuffer[MAX_WORD_LEN];
                localBuffer[0] = charset[i];
                if (brute(localBuffer, 1, maxLen))
                    local_found = 1;
            }

            local_worker_stop_time = MPI_Wtime();

            if (!local_found)
                printf("[Worker %d] Nada encontrado <%s> -> %f segundos.\n", my_rank, task_data.word, local_worker_stop_time - local_worker_start_time);
            else
                printf("[Worker %d] Palavra <%s> encontrada em %f segundos!\n", my_rank, task_data.word, local_worker_stop_time - local_worker_start_time);
        }
    }

    MPI_Finalize();
    return 0;
}