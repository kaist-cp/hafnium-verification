/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "hf/mpool.h"

#include <stdbool.h>

struct mpool_chunk {
	struct mpool_chunk *next_chunk;
	struct mpool_chunk *limit;
};

struct mpool_entry {
	struct mpool_entry *next;
};

static bool mpool_locks_enabled = false;

/**
 * Enables the locks protecting memory pools. Before this function is called,
 * the locks are disabled, that is, acquiring/releasing them is a no-op.
 */
void mpool_enable_locks(void)
{
	mpool_locks_enabled = true;
}

/**
 * Acquires the lock protecting the given memory pool, if locks are enabled.
 */
static void mpool_lock(struct mpool *p)
{
	if (mpool_locks_enabled) {
		sl_lock(&p->lock);
	}
}

/**
 * Releases the lock protecting the given memory pool, if locks are enabled.
 */
static void mpool_unlock(struct mpool *p)
{
	if (mpool_locks_enabled) {
		sl_unlock(&p->lock);
	}
}

static void mpool_inner_init(struct mpool_inner *inner, size_t entry_size)
{
	inner->entry_size = entry_size;
	inner->chunk_list = NULL;
	inner->entry_list = NULL;
}

/**
 * Initialises the given memory pool with the given entry size, which must be
 * at least the size of two pointers.
 *
 * All entries stored in the memory pool will be aligned to at least the entry
 * size.
 */
void mpool_init(struct mpool *p, size_t entry_size)
{
	mpool_inner_init(&p->inner, entry_size);
	p->fallback = NULL;
	sl_init(&p->lock);
}

static void mpool_inner_init_from(struct mpool_inner *inner,
				  struct mpool_inner *from)
{
	mpool_inner_init(inner, from->entry_size);
	inner->chunk_list = from->chunk_list;
	inner->entry_list = from->entry_list;

	from->chunk_list = NULL;
	from->entry_list = NULL;
}

/**
 * Initialises the given memory pool by replicating the properties of `from`. It
 * also pulls the chunk and free lists from `from`, consuming all its resources
 * and making them available via the new memory pool.
 */
void mpool_init_from(struct mpool *p, struct mpool *from)
{
	mpool_lock(from);
	mpool_inner_init_from(&p->inner, &from->inner);
	mpool_unlock(from);

	p->fallback = from->fallback;

	/**
	 * Note(HfO2): To prevent data race on the next line, caller must have
	 * full ownership of `from`.
	 */
	from->fallback = NULL;
}

/**
 * Initialises the given memory pool with a fallback memory pool if this pool
 * runs out of memory.
 */
void mpool_init_with_fallback(struct mpool *p, struct mpool *fallback)
{
	mpool_init(p, fallback->inner.entry_size);
	p->fallback = fallback;
}

static void mpool_inner_appends_to(struct mpool_inner *inner, struct mpool *to)
{
	struct mpool_entry *entry;
	struct mpool_chunk *chunk;

	/* Merge the freelist into the fallback. */
	entry = inner->entry_list;
	while (entry != NULL) {
		void *ptr = entry;

		entry = entry->next;
		mpool_free(to, ptr);
	}

	/* Merge the chunk list into the fallback. */
	chunk = inner->chunk_list;
	while (chunk != NULL) {
		void *ptr = chunk;
		size_t size = (uintptr_t)chunk->limit - (uintptr_t)chunk;

		chunk = chunk->next_chunk;
		mpool_add_chunk(to, ptr, size);
	}

	inner->chunk_list = NULL;
	inner->entry_list = NULL;
}

/**
 * Finishes the given memory pool, giving all free memory to the fallback pool
 * if there is one.
 */
void mpool_fini(struct mpool *p)
{
	if (!p->fallback) {
		return;
	}

	/**
	 * TODO(HfO2): don't need to lock if the mpool_fini requires
	 * full ownership of mpool.
	 */
	mpool_lock(p);
	mpool_inner_appends_to(&p->inner, p->fallback);
	mpool_unlock(p);
	p->fallback = NULL;
}

static bool mpool_inner_add_chunk(struct mpool_inner *inner, void *begin,
				  size_t size)
{
	struct mpool_chunk *chunk;
	uintptr_t new_begin;
	uintptr_t new_end;

	/* Round begin address up, and end address down. */
	new_begin = ((uintptr_t)begin + inner->entry_size - 1) /
		    inner->entry_size * inner->entry_size;
	new_end = ((uintptr_t)begin + size) / inner->entry_size *
		  inner->entry_size;

	/* Nothing to do if there isn't enough room for an entry. */
	if (new_begin >= new_end || new_end - new_begin < inner->entry_size) {
		return false;
	}

	chunk = (struct mpool_chunk *)new_begin;
	chunk->limit = (struct mpool_chunk *)new_end;

	chunk->next_chunk = inner->chunk_list;
	inner->chunk_list = chunk;

	return true;
}

/**
 * Adds a contiguous chunk of memory to the given memory pool. The chunk will
 * eventually be broken up into entries of the size held by the memory pool.
 *
 * Only the portions aligned to the entry size will be added to the pool.
 *
 * Returns true if at least a portion of the chunk was added to pool, or false
 * if none of the buffer was usable in the pool.
 */
bool mpool_add_chunk(struct mpool *p, void *begin, size_t size)
{
	bool ret;

	mpool_lock(p);
	ret = mpool_inner_add_chunk(&p->inner, begin, size);
	mpool_unlock(p);

	return ret;
}

/**
 * Allocates an entry from the given memory pool, if one is available.
 */
static void *mpool_inner_alloc(struct mpool_inner *inner)
{
	void *ret;
	struct mpool_chunk *chunk;
	struct mpool_chunk *new_chunk;

	/* Fetch an entry from the free list if one is available. */
	if (inner->entry_list != NULL) {
		struct mpool_entry *entry = inner->entry_list;

		inner->entry_list = entry->next;
		ret = entry;
		goto exit;
	}

	/* There was no free list available. Try a chunk instead. */
	chunk = inner->chunk_list;
	if (chunk == NULL) {
		/* The chunk list is also empty, we're out of entries. */
		ret = NULL;
		goto exit;
	}

	new_chunk =
		(struct mpool_chunk *)((uintptr_t)chunk + inner->entry_size);
	if (new_chunk >= chunk->limit) {
		inner->chunk_list = chunk->next_chunk;
	} else {
		*new_chunk = *chunk;
		inner->chunk_list = new_chunk;
	}

	ret = chunk;

exit:
	return ret;
}

/**
 * Allocates an entry from the given memory pool, if one is available. If there
 * isn't one available, try and allocate from the fallback if there is one.
 */
void *mpool_alloc(struct mpool *p)
{
	do {
		void *ret;

		mpool_lock(p);
		ret = mpool_inner_alloc(&p->inner);
		mpool_unlock(p);

		if (ret != NULL) {
			return ret;
		}

		p = p->fallback;
	} while (p != NULL);

	return NULL;
}

static void mpool_inner_free(struct mpool_inner *inner, void *ptr)
{
	struct mpool_entry *e = ptr;

	/* Store the newly freed entry in the front of the free list. */
	e->next = inner->entry_list;
	inner->entry_list = e;
}

/**
 * Frees an entry back into the memory pool, making it available for reuse.
 *
 * This is meant to be used for freeing single entries. To free multiple
 * entries, one must call mpool_add_chunk instead.
 */
void mpool_free(struct mpool *p, void *ptr)
{
	mpool_lock(p);
	mpool_inner_free(&p->inner, ptr);
	mpool_unlock(p);
}

/**
 * Allocates a number of contiguous and aligned entries. If a suitable
 * allocation could not be found, the fallback will not be used even if there is
 * one.
 */
void *mpool_inner_alloc_contiguous(struct mpool_inner *inner, size_t count,
				   size_t align)
{
	struct mpool_chunk **prev;
	void *ret = NULL;

	align *= inner->entry_size;

	/*
	 * Go through the chunk list in search of one with enough room for the
	 * requested allocation
	 */
	prev = &inner->chunk_list;
	while (*prev != NULL) {
		uintptr_t start;
		struct mpool_chunk *new_chunk;
		struct mpool_chunk *chunk = *prev;

		/* Round start address up to the required alignment. */
		start = (((uintptr_t)chunk + align - 1) / align) * align;

		/*
		 * Calculate where the new chunk would be if we consume the
		 * requested number of entries. Then check if this chunk is big
		 * enough to satisfy the request.
		 */
		new_chunk = (struct mpool_chunk *)(start +
						   (count * inner->entry_size));
		if (new_chunk <= chunk->limit) {
			/* Remove the consumed area. */
			if (new_chunk == chunk->limit) {
				*prev = chunk->next_chunk;
			} else {
				*new_chunk = *chunk;
				*prev = new_chunk;
			}

			/*
			 * Add back the space consumed by the alignment
			 * requirement, if it's big enough to fit an entry.
			 */
			if (start - (uintptr_t)chunk >= inner->entry_size) {
				chunk->next_chunk = *prev;
				*prev = chunk;
				chunk->limit = (struct mpool_chunk *)start;
			}

			ret = (void *)start;
			break;
		}

		prev = &chunk->next_chunk;
	}

	return ret;
}

/**
 * Allocates a number of contiguous and aligned entries. This is a best-effort
 * operation and only succeeds if such entries can be found in the chunks list
 * or the chunks of the fallbacks (i.e., the entry list is never used to satisfy
 * these allocations).
 *
 * The alignment is specified as the number of entries, that is, if `align` is
 * 4, the alignment in bytes will be 4 * entry_size.
 *
 * The caller can eventually free the returned entries by calling
 * mpool_add_chunk.
 */
void *mpool_alloc_contiguous(struct mpool *p, size_t count, size_t align)
{
	do {
		void *ret;
		mpool_lock(p);
		ret = mpool_inner_alloc_contiguous(&p->inner, count, align);
		mpool_unlock(p);

		if (ret != NULL) {
			return ret;
		}

		p = p->fallback;
	} while (p != NULL);

	return NULL;
}
