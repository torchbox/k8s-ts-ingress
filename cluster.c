/* vim:set sw=8 ts=8 noet: */
/*
 * Copyright (c) 2016-2017 Torchbox Ltd.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include	"api.h"

cluster_t *
cluster_make(void)
{
cluster_t	*ret;
	if ((ret = calloc(1, sizeof(*ret))) == NULL)
		return NULL;
	if ((ret->cs_namespaces = hash_new(127, (hash_free_fn) namespace_free)) == NULL) {
		free(ret);
		return NULL;
	}
	return ret;
}

namespace_t *
cluster_get_namespace(cluster_t *cs, const char *name)
{
namespace_t	*ret;

	if ((ret = hash_get(cs->cs_namespaces, name)) == NULL) {
		if ((ret = namespace_make()) == NULL)
			return NULL;
		hash_set(cs->cs_namespaces, name, ret);
	}

	return ret;
}
