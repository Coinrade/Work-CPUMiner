/* Invented by our great leader */
#include <miner.h>

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>


#include <sha3/sph_sha2.h>
#include <sha3/sph_blake.h>


//#define DEBUG_ALGO

void workhash(void *output, const void *input)
{
	sph_sha512_context    	ctx_sha;
	sph_blake512_context    ctx_blake;

	uint32_t _ALIGN(128) hash[16];

	sph_sha512_init			(&ctx_sha);
	sph_sha512				(&ctx_sha, input, 80);
	sph_sha512_close 		(&ctx_sha, hash);

	sph_blake512_init		(&ctx_blake);
	sph_blake512 			(&ctx_blake, hash, 64);
	sph_blake512_close		(&ctx_blake, hash);

	memcpy(output, hash, 32);
}

int scanhash_work(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t _ALIGN(64) hash[8];
	uint32_t _ALIGN(64) endiandata[20];
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;

	const uint32_t Htarg = ptarget[7];
	const uint32_t first_nonce = pdata[19];
	uint32_t nonce = first_nonce;
	volatile uint8_t *restart = &(work_restart[thr_id].restart);

	if (opt_benchmark)
		ptarget[7] = 0x0cff;

	for (int k=0; k < 19; k++)
		be32enc(&endiandata[k], pdata[k]);

	do {
		be32enc(&endiandata[19], nonce);
		workhash(hash, endiandata);

		if (hash[7] <= Htarg && fulltest(hash, ptarget)) {
			work_set_target_ratio(work, hash);
			pdata[19] = nonce;
			*hashes_done = pdata[19] - first_nonce;
			return 1;
		}
		nonce++;

	} while (nonce < max_nonce && !(*restart));

	pdata[19] = nonce;
	*hashes_done = pdata[19] - first_nonce + 1;
	return 0;
}
