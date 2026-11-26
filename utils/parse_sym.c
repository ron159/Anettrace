// SPDX-License-Identifier: MulanPSL-2.0

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "parse_sym.h"
#include "sys_utils.h"

static char *proc_syms = NULL;
struct sym_result *result_list;
struct loc_result *loc_list;

static int sym_init_data()
{
	size_t size = 1024 * 1024 * 4; // begin with 4M
	char *cur, *tmp;
	size_t count;
	FILE *f;

	if (proc_syms)
		return 0;

	f = fopen("/proc/kallsyms", "r");
	if (!f) {
		pr_err("/proc/kallsyms is not founded!\n");
		exit(-1);
	}

	proc_syms = malloc(size + 1);
	cur = proc_syms;
	while (true) {
		size_t offset;

		count = fread(cur, sizeof(char), size + proc_syms - cur, f);
		cur += count;
		if (feof(f))
			break;

		offset = cur - proc_syms;
		size <<= 1;
		tmp = realloc(proc_syms, size + 1);
		cur = tmp + offset;
		proc_syms = tmp;
	}
	*cur = '\0';
	fclose(f);

	return 0;
}

static void sym_add_cache(struct sym_result *result)
{
	if (!result_list) {
		result_list = result;
		result->next = NULL;
		return;
	}
	result->next = result_list;
	result_list = result;
}

static struct sym_result *sym_lookup_cache(__u64 pc, bool exact)
{
	struct sym_result *head = result_list, *sym = NULL;
	while (head) {
		if (!exact) {
			if (pc >= head->start && pc < head->end) {
				if (head->pc == pc)
					return head;
				sym = head;
				break;
			}
		} else {
			if (head->start == pc)
				return head;
		}
		head = head->next;
	}
	if (!sym)
		return NULL;
	head = malloc(sizeof(*head));
	if (!head)
		return NULL;
	memcpy(head, sym, sizeof(*head));
	head->pc = pc;
	sprintf(head->desc, "%s+0x%llx", head->name, pc - head->start);
	sym_add_cache(head);
	return head;
}

static struct sym_result *sym_lookup_proc(__u64 pc, bool exact)
{
	char cname[MAX_SYM_LENGTH], pname[MAX_SYM_LENGTH] = {}, *line;
	bool has_prev = false;
	__u64 cpc, ppc = 0;

	if (sym_init_data())
		return NULL;

	line = proc_syms;
	while (*line) {
		struct sym_result *result;
		char tname, *line_end;
		int count;

		line_end = strchr(line, '\n');
		if (line_end)
			*line_end = '\0';
		count = sscanf(line, "%llx %c %255s", &cpc, &tname, cname);
		if (line_end)
			*line_end = '\n';
		if (count != 3 || (tname != 'T' && tname != 't'))
			goto next_line;

		if (!has_prev) {
			strcpy(pname, cname);
			ppc = cpc;
			has_prev = true;
			goto next_line;
		}

		if (exact) {
			if (ppc != pc)
				goto update_prev;
		} else {
			if (pc < ppc || pc >= cpc)
				goto update_prev;
		}

		result = malloc(sizeof(*result));
		if (!result)
			return NULL;

		strcpy(result->name, pname);
		result->start = ppc;
		result->end = cpc;
		result->pc = pc;
		sprintf(result->desc, "%s+0x%llx", result->name,
			pc - result->start);
		sym_add_cache(result);
		return result;

update_prev:
		strcpy(pname, cname);
		ppc = cpc;
next_line:
		if (!line_end)
			break;
		line = line_end + 1;
	}

	return NULL;
}

struct sym_result *sym_parse(__u64 pc)
{
	if (!pc)
		return NULL;
	return sym_lookup_cache(pc, false) ?: sym_lookup_proc(pc, false);
}

struct sym_result *sym_parse_exact(__u64 pc)
{
	if (!pc)
		return NULL;
	return sym_lookup_cache(pc, true) ?: sym_lookup_proc(pc, true);
}

int sym_search_pattern(const char *name, char *result, bool partial)
{
	char func[128], module[128], search[128], *target;
	int count;

	sym_init_data();

	sprintf(search, " %s", name);
	target = proc_syms;
	while (true) {
		target = strstr(target, search);
		if (!target)
			break;

		count = sscanf(target, " %s [%[^]]]", func, module);
		target++;

		if (count <= 0)
			continue;

		if (partial && strncmp(func, name, strlen(name)) == 0)
				goto found;
		if (!partial && strcmp(func, name) == 0)
				goto found;
	}

	return SYM_NOT_EXIST;
found:
	if (result)
		strcpy(result, func);

	return count == 2 ? SYM_MODULE : SYM_KERNEL;
}

struct symbol_record {
	const char *name;
	size_t length;
	char type;
	bool module;
};

static struct symbol_record *name_index;
static size_t name_count;
static struct symbol_record *wanted_names;
static size_t wanted_count;

/* Keep the original address-ordered text intact for stack symbolization. */
static bool next_symbol_record(const char **next, struct symbol_record *record)
{
	while (**next) {
		const char *line = *next;
		const char *end = strchr(line, '\n');
		const char *p = line;

		if (!end)
			end = line + strlen(line);
		*next = *end ? end + 1 : end;
		while (end > line && isspace((unsigned char)end[-1]))
			end--;
		while (p < end && isxdigit((unsigned char)*p))
			p++;
		if (p == line || p == end || !isspace((unsigned char)*p))
			continue;
		while (p < end && isspace((unsigned char)*p))
			p++;
		if (p == end || (!isalpha((unsigned char)*p) && *p != '?'))
			continue;
		record->type = *p++;
		if (p == end || !isspace((unsigned char)*p))
			continue;
		while (p < end && isspace((unsigned char)*p))
			p++;
		record->name = p;
		while (p < end && !isspace((unsigned char)*p))
			p++;
		record->length = p - record->name;
		while (p < end && isspace((unsigned char)*p))
			p++;
		record->module = p < end;
		if (record->module) {
			if (end - p < 3 || *p != '[' || end[-1] != ']')
				continue;
			for (p++; p < end - 1; p++)
				if (isspace((unsigned char)*p) || *p == '[' || *p == ']')
					break;
			if (p != end - 1)
				continue;
		}
		return true;
	}
	return false;
}

bool sym_kernel_text_exists(const char *name)
{
	struct symbol_record record;
	size_t length = strlen(name);
	const char *next;

	if (sym_init_data())
		return false;
	next = proc_syms;
	while (next_symbol_record(&next, &record)) {
		if (record.type == 'T' && !record.module &&
		    record.length == length && !memcmp(record.name, name, length))
			return true;
	}
	return false;
}

static int compare_symbol_names(const void *left, const void *right)
{
	const struct symbol_record *a = left, *b = right;
	size_t length = a->length < b->length ? a->length : b->length;
	int order = memcmp(a->name, b->name, length);

	return order ? order : (a->length > b->length) - (a->length < b->length);
}

static size_t base_length(const struct symbol_record *record)
{
	const char *dot = memchr(record->name, '.', record->length);

	return dot ? (size_t)(dot - record->name) : record->length;
}

static bool indexed_family(const struct symbol_record *record)
{
	struct symbol_record key = { .name = record->name, .length = base_length(record) };

	return bsearch(&key, wanted_names, wanted_count, sizeof(*wanted_names),
		       compare_symbol_names) != NULL;
}

void sym_release_name_index(void)
{
	free(name_index);
	name_index = NULL;
	name_count = 0;
	free(wanted_names);
	wanted_names = NULL;
	wanted_count = 0;
}

/* The caller keeps the base names (up to the first dot) alive until release.
 * Save all types in each requested family to detect ambiguous attach names. */
void sym_prepare_name_index(const char *const *names, size_t count)
{
	const char *next;
	struct symbol_record record;
	size_t capacity = 0, i;

	sym_release_name_index();
	if (!count || sym_init_data())
		return;
	wanted_names = calloc(count, sizeof(*wanted_names));
	if (!wanted_names)
		return;
	wanted_count = count;
	for (i = 0; i < count; i++) {
		wanted_names[i].name = names[i];
		wanted_names[i].length = strcspn(names[i], ".");
	}
	qsort(wanted_names, count, sizeof(*wanted_names), compare_symbol_names);

	next = proc_syms;
	while (next_symbol_record(&next, &record)) {
		if (!indexed_family(&record))
			continue;
		if (name_count == capacity) {
			struct symbol_record *grown;

			if (capacity > (size_t)-1 / sizeof(*name_index) / 2)
				goto fallback;
			capacity = capacity ? capacity * 2 : count;
			grown = realloc(name_index, capacity * sizeof(*name_index));
			if (!grown)
				goto fallback;
			name_index = grown;
		}
		name_index[name_count++] = record;
	}
	if (name_count)
		qsort(name_index, name_count, sizeof(*name_index), compare_symbol_names);
	return;
fallback:
	sym_release_name_index();
}

static size_t symbol_lower_bound(const struct symbol_record *key)
{
	size_t lo = 0, hi = name_count;

	while (lo < hi) {
		size_t mid = lo + (hi - lo) / 2;
		if (compare_symbol_names(&name_index[mid], key) < 0)
			lo = mid + 1;
		else
			hi = mid;
	}
	return lo;
}

int sym_search_unique(const char *name, char *result, size_t result_size, bool partial)
{
	struct symbol_record key, record, match = {};
	const char *next;
	unsigned matches = 0;
	bool functions_only = true, indexed;
	size_t index;

	if (!name || !*name || !result || !result_size || sym_init_data())
		goto unavailable;
	key.name = name;
	key.length = strlen(name);
	/* An arbitrary prefix without a dot can span multiple base names. */
	indexed = wanted_names && (!partial || memchr(name, '.', key.length)) &&
		  indexed_family(&key);

scan_records:
	index = symbol_lower_bound(&key);
	next = proc_syms;
	for (;;) {
		if (indexed) {
			if (index == name_count)
				break;
			record = name_index[index++];
		} else if (!next_symbol_record(&next, &record)) {
			break;
		}
		if (record.length < key.length || memcmp(record.name, key.name, key.length) ||
		    (!partial && record.length != key.length)) {
			if (indexed)
				break;
			continue;
		}
		if (functions_only && !strchr("TtWw", record.type))
			continue;
		if (++matches > 1) {
			result[0] = '\0';
			return SYM_AMBIGUOUS;
		}
		match = record;
	}
	if (matches && functions_only) {
		/* Attachment counts same-name data records as well as functions. */
		key = match;
		partial = false;
		functions_only = false;
		matches = 0;
		goto scan_records;
	}
	if (matches && match.length < result_size) {
		memmove(result, match.name, match.length);
		result[match.length] = '\0';
		return match.module ? SYM_MODULE : SYM_KERNEL;
	}
unavailable:
	if (result && result_size)
		result[0] = '\0';
	return SYM_NOT_EXIST;
}
