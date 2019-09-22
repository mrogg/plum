

import os
import glob
import time

import MySQLdb


def get_cursor(cfg):
    """Get a cursor, right quick."""
    db_props = dict([(k,v) for (k,v) in cfg.items('db')
                     if k in "hostdbuserpasswd"])
    return MySQLdb.connect(**db_props).cursor()

        
def cleandb(cfg, log):
    """Get files older than secs configured in config and delete them. 

    Also delete traffic older than secs configure in config.
    """
    now = time.time()

    # DB Connection for storing conversations and stats.
    cursor = get_cursor(cfg)
    try:

        # Remove old data.
        sql = """
            select
                id
            from tcp_conversations
            where start_timestamp < %f 
        """ % (now - cfg.getint('cleanup', 'shelflife'))
        log.info(sql)
        cursor.execute(sql)
        rows = cursor.fetchall()
        to_del = [str(r[0]) for r in rows]

        if not to_del:
             return

        trn_sql = """
            delete
            from http_transactions
            where conversation_id in (%s)
        """ % ",".join(to_del)
        log.info(trn_sql)
        cursor.execute(trn_sql)

        qry_sql = """
            delete
            from sql_queries
            where conversation_id in (%s)
        """ % ",".join(to_del)
        log.info(qry_sql)
        cursor.execute(qry_sql)

        cnv_sql = """
            delete 
            from tcp_conversations
            where id in (%s)
        """ % ",".join(to_del)   
        log.info(cnv_sql)
        cursor.execute(cnv_sql)

    finally:
        cursor.connection.close()

