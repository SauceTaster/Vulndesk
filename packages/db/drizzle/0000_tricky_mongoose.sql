CREATE TABLE "comments" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"document_id" uuid NOT NULL,
	"author" text NOT NULL,
	"slug" text NOT NULL,
	"hypertext" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "documents" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"section" text NOT NULL,
	"doc_id" text NOT NULL,
	"cve_id" text,
	"state" text,
	"author" text,
	"body" jsonb NOT NULL,
	"slug" text,
	"full_slug" text,
	"parent_id" uuid,
	"legacy_mongo_id" text,
	"version" integer DEFAULT 0 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "files" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"document_id" uuid NOT NULL,
	"name" text NOT NULL,
	"size" integer,
	"comment" text,
	"uploaded_by" text,
	"type" text,
	"subtype" text,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "users" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" text NOT NULL,
	"username" text NOT NULL,
	"email" text NOT NULL,
	"emoji" text NOT NULL,
	"password_hash" text NOT NULL,
	"priv" integer DEFAULT 1 NOT NULL,
	"group" text,
	"legacy_mongo_id" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "comments" ADD CONSTRAINT "comments_document_id_documents_id_fk" FOREIGN KEY ("document_id") REFERENCES "public"."documents"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "files" ADD CONSTRAINT "files_document_id_documents_id_fk" FOREIGN KEY ("document_id") REFERENCES "public"."documents"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "comments_document_id_idx" ON "comments" USING btree ("document_id");--> statement-breakpoint
CREATE UNIQUE INDEX "documents_section_doc_id_key" ON "documents" USING btree ("section","doc_id");--> statement-breakpoint
CREATE UNIQUE INDEX "documents_legacy_mongo_id_key" ON "documents" USING btree ("legacy_mongo_id");--> statement-breakpoint
CREATE INDEX "documents_cve_id_idx" ON "documents" USING btree ("cve_id");--> statement-breakpoint
CREATE INDEX "documents_state_idx" ON "documents" USING btree ("state");--> statement-breakpoint
CREATE INDEX "documents_body_gin" ON "documents" USING gin ("body" jsonb_path_ops);--> statement-breakpoint
CREATE INDEX "files_document_id_idx" ON "files" USING btree ("document_id");--> statement-breakpoint
CREATE UNIQUE INDEX "users_username_key" ON "users" USING btree ("username");--> statement-breakpoint
CREATE UNIQUE INDEX "users_legacy_mongo_id_key" ON "users" USING btree ("legacy_mongo_id");