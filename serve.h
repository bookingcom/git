#ifndef SERVE_H
#define SERVE_H

struct argv_array;
extern int has_capability(const struct argv_array *keys, const char *capability,
			  const char **value);

struct serve_options {
	unsigned advertise_capabilities;
	unsigned stateless_rpc;

	/*
	 * Some operations may need to know the context when looking up config;
	 * e.g., set this to "uploadpack" to respect "uploadpack.hiderefs" (as
	 * opposed to "receive.hiderefs").
	 */
	const char *config_context;
};
#define SERVE_OPTIONS_INIT { 0 }
extern void serve(struct serve_options *options);

#endif /* SERVE_H */
