""" plum.groomer - groom the database

The terminology of 'defect' and 'normal' are used to describe data that
we find unusual (and thus interesting and kept longer) and data that are 
as expected (and thus presumably not as interesting and not kept as long), 
respectively. To understand what we are considering defective and normal, 
take a look at the queries used in this module. The durations for which 
normal and defective data are kept are controlled by 2 config settings:

[grooming]
normal_shelf_life: SECONDS
defect_shelf_life: SECONDS

"""

import os
import glob
import time

import MySQLdb


def get_cursor(cfg):
    """Get a cursor, right quick."""
    db_props = dict([(k,v) for (k,v) in cfg.items('db')
                     if k in "hostdbuserpasswd"])
    return MySQLdb.connect(**db_props).cursor()


def run_and_log_sql(cursor, sql, log, message):
    """Run the query between logging before and after (reveals query run time)."""
    log.info('CLEANUP - START %s' % message)
    log.info(sql)
    cursor.execute(sql)
    log.info('CLEANUP - END %s' % message)

        
def groom(cfg, log):
    """Get files older than secs configured in config and delete them. 

    Also delete traffic older than secs configure in config.
    """
    now = time.time()
    normal_shelf_life = cfg.getint('grooming', 'normal_shelf_life')
    defect_shelf_life = cfg.getint('grooming', 'defect_shelf_life')
    cursor = get_cursor(cfg)
    try:
        # Remove normal transactions and queries older than normal shelf life
        sql = """
            delete from http_transactions 
	    where status in 
            (100,101,102,
             200,201,202,203,204,205,206,207,
             300,301,302,303,304,305,306,307) 
	    and request_timestamp < %s
	    and response_time < 1;
        """ % (now - normal_shelf_life)
        run_and_log_sql(cursor, sql, log, "DELETE NORMAL TRANSACTIONS")
        sql = """
            delete from sql_queries
	    where 
	    first_timestamp < %s
	    and response_time < 1;
        """ % (now - normal_shelf_life)
        run_and_log_sql(cursor, sql, log, "DELETE NORMAL QUERIES")

        # Remove everything older than defect_shelf_life
        sql = """
        select
            id
        from tcp_conversations
        where start_timestamp < %s
        """ % (now - defect_shelf_life)
        run_and_log_sql(cursor, sql, log, "SELECT DEFECT CONVERSATIONS")
        deletable_conversations = [str(r[0]) for r in cursor.fetchall()]
        if deletable_conversations:
            batch_size = 5000
            batch_indexes = xrange(0, len(deletable_conversations), batch_size)
            batches = (deletable_conversations[i:i+batch_size] 
	               for i in batch_indexes)
	    for conversations_to_delete in batches: 
                # Delete transactions and queries that are part of old 
                # conversations per previous query
                sql = """
                    delete
                    from http_transactions
                    where conversation_id in (%s)
                """ % ",".join(conversations_to_delete)
                run_and_log_sql(cursor, sql, log, "DELETE DEFECT TRANSACTIONS")

                sql = """
                    delete
                    from sql_queries
                    where conversation_id in (%s)
                """ % ",".join(conversations_to_delete)
                run_and_log_sql(cursor, sql, log, "DELETE DEFECT QUERIES")

                # Now, delete the old conversations
                # (Skip this and let the non-linked convo's delete do it?)
                sql = """
                    delete 
                    from tcp_conversations
                    where id in (%s)
                """ % ",".join(conversations_to_delete)
                run_and_log_sql(cursor, sql, log, "DELETE DEFECT CONVERSATIONS")

        # Delete normal unlinked conversations. (creates and removes indexes)
        log.info('CLEANUP - START DELETE NON-LINKED NORMAL CONVERSATIONS')

        sql = """
        create index idx_conversation_id on http_transactions (conversation_id);
        """
        log.info(sql)
        cursor.execute(sql)
        sql = """
        create index idx_conversation_id on sql_queries (conversation_id);
        """
        log.info(sql)
        cursor.execute(sql)

         
        sql = """
        delete c from tcp_conversations as c 
            left join http_transactions as t 
                on c.id = t.conversation_id
            left join sql_queries as q
                on c.id = q.conversation_id
        where 
                t.conversation_id is null
            and q.conversation_id is null 
            and c.retransmits_in = 0 
            and c.lost_packets_in = 0 
            and c.retransmits_out = 0 
            and c.lost_packets_out = 0
        """
        log.info(sql)
        cursor.execute(sql)

        sql = "drop index idx_conversation_id on http_transactions"
        log.info(sql)
        cursor.execute(sql)
        sql = "drop index idx_conversation_id on sql_queries"
        log.info(sql)
        cursor.execute(sql)

        log.info('CLEANUP - END DELETE NON-LINKED NORMAL CONVERSATIONS')

    finally:
        cursor.connection.close()

