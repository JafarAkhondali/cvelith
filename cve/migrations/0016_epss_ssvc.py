from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('cve', '0015_ssvc'),
    ]

    operations = [
        # Create the base partitioned table
        migrations.RunSQL(
            """
            CREATE TABLE epss (
                cve VARCHAR(20) NOT NULL,
                epss NUMERIC(30, 15) NOT NULL,
                percentile FLOAT NOT NULL,
                model VARCHAR(20) NOT NULL,
                date DATE NOT NULL,
                PRIMARY KEY (cve, date)  -- Primary key includes partitioning column
            ) PARTITION BY HASH (cve);
            """,
            reverse_sql="DROP TABLE epss;"
        ),
        # Create hash partitions
        migrations.RunSQL(
            "\n".join(
                f"""
                CREATE TABLE epss_hash_{i} PARTITION OF epss
                FOR VALUES WITH (MODULUS 16, REMAINDER {i});
                """ for i in range(16)
            ),
            reverse_sql="\n".join(
                f"DROP TABLE epss_hash_{i};" for i in range(16)
            )
        ),
        # Add indexes to partitions
        migrations.RunSQL(
            "\n".join(
                f"""
                CREATE INDEX idx_epss_hash_{i}_cve ON epss_hash_{i} (cve);
                """ for i in range(16)
            ),
            reverse_sql="\n".join(
                f"DROP INDEX idx_epss_hash_{i}_cve;" for i in range(16)
            )
        ),
    ]


