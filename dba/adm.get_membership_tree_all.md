### 🛡️ PostgreSQL Privilege Forensics: Complete Role Membership & Access Rights Analysis
### Анализ привилегий PostgreSQL: Полное дерево членства и прав доступа  

#### Назначение функции

Функция `adm.get_membership_tree_all` предназначена для комплексного анализа привилегий в PostgreSQL. Она позволяет отслеживать права доступа на объекты БД (таблицы, функции) с учётом всей иерархии наследования ролей. 

**Ключевые возможности:**
- Отслеживание полной цепочки наследования привилегий
- Идентификация прямых и косвенных прав доступа
- Анализ возможностей передачи привилегий (GRANT OPTION)
- Выявление путей эскалации привилегий

#### Сигнатура функции

```sql
CREATE OR REPLACE FUNCTION adm.get_membership_tree_all(
    username varchar DEFAULT '%',
    schema_name varchar DEFAULT '%', 
    object_name varchar DEFAULT '%'
)
RETURNS TABLE (
    is_user boolean,           -- Является ли учётной записью пользователя
    granted_to name,           -- Роль, которой предоставлены права
    priv varchar,              -- Тип привилегии
    priv_received text,        -- Способ получения: OWNER/DIRECTLY/INDIRECTLY
    branch_recursive text,     -- Полная цепочка наследования
    grantor text,              -- Роль-источник привилегии
    grantee text,              -- Роль-получатель привилегии
    object_schema text,        -- Схема объекта
    object_name text,          -- Имя объекта
    is_grantable text,         -- Возможность передачи прав
    is_superuser boolean       -- Является ли суперпользователем
)
LANGUAGE sql
SECURITY DEFINER
VOLATILE
AS $$
-- Версия: 2.0.0 @sqlmaster
   WITH RECURSIVE membership_tree(grpid, userid, lvl, rolname, branch) AS (
       -- Базовый случай: начальная роль
       SELECT pg_roles.oid, pg_roles.oid, -1 AS lvl, r.rolname, r.rolname::text AS branch
         FROM pg_catalog.pg_roles
         JOIN pg_catalog.pg_roles r ON r.oid = pg_roles.oid
       UNION ALL
       -- Рекурсивный случай: наследование ролей
       SELECT m_1.roleid, t_1.userid, lvl + 1, r.rolname, (r.rolname || '->' || branch)::text
         FROM membership_tree t_1
         JOIN pg_catalog.pg_auth_members m_1 ON m_1.member = t_1.grpid
         JOIN pg_catalog.pg_roles r ON r.oid = m_1.roleid
        WHERE lvl < 99  -- Защита от бесконечной рекурсии
   ),
   members AS (
       -- Формирование списка членства с атрибутами ролей
       SELECT DISTINCT t.userid, r.rolname AS usrname, t.grpid, t.rolname AS grpname, 
              lvl, r.rolcanlogin, r.rolsuper, branch
         FROM membership_tree t
         JOIN pg_catalog.pg_roles r ON r.oid = t.userid
   ),
   privileges AS (
       -- Привилегии на таблицы
       SELECT privilege_type, grantor::text, grantee::text, 
              table_schema AS object_schema, table_name AS object_name, is_grantable
         FROM information_schema.role_table_grants
        WHERE grantee IN (SELECT grpname FROM members)
          AND table_schema LIKE schema_name
          AND table_name LIKE object_name
       UNION ALL
       -- Привилегии на функции
       SELECT privilege_type, grantor::text, grantee::text, 
              specific_schema AS object_schema, routine_name AS object_name, is_grantable
         FROM information_schema.routine_privileges
        WHERE grantee IN (SELECT grpname FROM members)
          AND specific_schema LIKE schema_name
          AND routine_name LIKE object_name
   )
   -- Финальный результат с классификацией привилегий
   SELECT m.rolcanlogin AS is_user
        , m.usrname AS granted_to
        , p.privilege_type AS priv
        , CASE WHEN m.lvl = -1 THEN 'OWNER' 
               WHEN m.lvl = 0 THEN 'DIRECTLY' 
               ELSE 'INDIRECTLY' END AS priv_received
        , m.branch as branch_recursive
        , p.grantor
        , p.grantee
        , p.object_schema
        , p.object_name
        , CASE WHEN p.grantee = m.usrname AND p.is_grantable = 'YES' THEN 'YES' ELSE 'NO' END AS is_grantable
        , m.rolsuper AS is_superuser
     FROM members m
LEFT JOIN privileges p ON p.grantee = m.grpname
    WHERE m.usrname LIKE username
 ORDER BY m.usrname, m.lvl;
$$;

COMMENT ON FUNCTION adm.get_membership_tree_all(varchar, varchar, varchar) IS
$$
- Версия: 2.0.0 @sqlmaster
Полный анализ привилегий PostgreSQL: дерево членства в ролях и права на объекты.
-
Параметры (все необязательные, поддерживают wildcard '%'):
- username:     роль/пользователь (например, 'role_example' или '%')
- schema_name:  схема (например, 'public' или '%')
- object_name:  объект — таблица или функция (например, 'my_table' или '%')
-
Возвращает детализированную информацию о правах доступа с указанием цепочки наследования ролей.
-
Примеры использования:
- SELECT * FROM adm.get_membership_tree_all();                                  -- все права на все объекты во всех схемах
- SELECT * FROM adm.get_membership_tree_all('role_example');                     -- права для роли 'role_example' на все объекты
- SELECT * FROM adm.get_membership_tree_all('role_example', 'test');             -- права для роли в схеме 'test'
- SELECT * FROM adm.get_membership_tree_all('role_example', 'test', 'table_3');  -- права на конкретную таблицу
- SELECT * FROM adm.get_membership_tree_all('role_example', 'test', 'check_unlogged_tables'); -- права на функцию
- SELECT * FROM adm.get_membership_tree_all('%', '%', 'table_3');                -- поиск объекта с именем 'table_3' в любой схеме и у любой роли
-
$$;
```

#### 📊 Примеры использования с реальными результатами

##### Пример 1: Все права роли на все объекты

```sql
-- Все права роли roletest на все объекты во всех схемах
SELECT * FROM adm.get_membership_tree_all('roletest');
```

**Результат:**
```
is_user|granted_to|priv      |priv_received|branch_recursive                                      |grantor           |grantee               |object_schema           |object_name                                                    |is_grantable|is_superuser|
-------+----------+----------+-------------+------------------------------------------------------+------------------+----------------------+------------------------+---------------------------------------------------------------+------------+------------+
true   |roletest  |          |OWNER        |roletest                                              |                  |                      |                        |                                                               |NO          |false       |
true   |roletest  |          |DIRECTLY     |App-xxx-P-Role-RUNSUR->roletest                       |                  |                      |                        |                                                               |NO          |false       |
true   |roletest  |          |DIRECTLY     |App-xxx-P-DevRole-RDD->roletest                       |                  |                      |                        |                                                               |NO          |false       |
true   |roletest  |          |DIRECTLY     |sync_ldap_users->roletest                             |                  |                      |                        |                                                               |NO          |false       |
true   |roletest  |TRUNCATE  |DIRECTLY     |App-xxx-P-DevRole-xxxx->roletest                      |role-for-example-1|App-xxx-P-DevRole-xxxx|xxxx_cdl_wrk            |buf_2379_test_all                                              |NO          |false       |
true   |roletest  |REFERENCES|DIRECTLY     |App-xxx-P-DevRole-xxxx->roletest                      |role-for-example-1|App-xxx-P-DevRole-xxxx|xxxx_cdl_wrk            |buf_2379_test_all                                              |NO          |false       |
```

##### Пример 2: Права роли на объекты в конкретной схеме

```sql
-- Все права roletest на объекты в схеме xxxx_cdl_wrk
SELECT * FROM adm.get_membership_tree_all('roletest','xxxx_cdl_wrk');
```

**Результат:**
```
is_user|granted_to|priv      |priv_received|branch_recursive                                      |grantor           |grantee               |object_schema|object_name                                        |is_grantable|is_superuser|
-------+----------+----------+-------------+------------------------------------------------------+------------------+----------------------+-------------+---------------------------------------------------+------------+------------+
true   |roletest  |          |OWNER        |roletest                                              |                  |                      |             |                                                   |NO          |false       |
true   |roletest  |          |DIRECTLY     |App-xxx-P-Role-RUNSUR->roletest                       |                  |                      |             |                                                   |NO          |false       |
true   |roletest  |TRUNCATE  |DIRECTLY     |App-xxx-P-DevRole-xxxx->roletest                      |role-for-example-1|App-xxx-P-DevRole-xxxx|xxxx_cdl_wrk |buf_2379_test_all                                  |NO          |false       |
true   |roletest  |REFERENCES|DIRECTLY     |App-xxx-P-DevRole-xxxx->roletest                      |role-for-example-1|App-xxx-P-DevRole-xxxx|xxxx_cdl_wrk |buf_2379_test_all                                  |NO          |false       |
true   |roletest  |INSERT    |DIRECTLY     |App-xxx-P-DevRole-xxxx->roletest                      |role-for-example-1|App-xxx-P-DevRole-xxxx|xxxx_cdl_wrk |buf_2379_test_1b1                                  |NO          |false       |
```

##### Пример 3: Права на конкретный объект

```sql
-- Все права roletest на конкретную таблицу
SELECT * FROM adm.get_membership_tree_all('roletest','xxxx_cdl_wrk','buf_2379_test_all');
```

**Результат:**
```
is_user|granted_to|priv      |priv_received|branch_recursive                                      |grantor           |grantee               |object_schema|object_name      |is_grantable|is_superuser|
-------+----------+----------+-------------+------------------------------------------------------+------------------+----------------------+-------------+-----------------+------------+------------+
true   |roletest  |TRUNCATE  |DIRECTLY     |App-xxx-P-DevRole-xxxx->roletest                      |role-for-example-1|App-xxx-P-DevRole-xxxx|xxxx_cdl_wrk |buf_2379_test_all|NO          |false       |
true   |roletest  |REFERENCES|DIRECTLY     |App-xxx-P-DevRole-xxxx->roletest                      |role-for-example-1|App-xxx-P-DevRole-xxxx|xxxx_cdl_wrk |buf_2379_test_all|NO          |false       |
true   |roletest  |TRIGGER   |DIRECTLY     |App-xxx-P-DevRole-xxxx->roletest                      |role-for-example-1|App-xxx-P-DevRole-xxxx|xxxx_cdl_wrk |buf_2379_test_all|NO          |false       |
true   |roletest  |UPDATE    |DIRECTLY     |App-xxx-P-DevRole-xxxx->roletest                      |role-for-example-1|App-xxx-P-DevRole-xxxx|xxxx_cdl_wrk |buf_2379_test_all|NO          |false       |
```

##### Пример 4: Поиск объектов в разных схемах

```sql
-- Поиск таблицы test во всех схемах для роли gpbu44973
SELECT * FROM adm.get_membership_tree_all('gpbu44973','%','test');
```

**Результат (косвенные привилегии):**
```
is_user|granted_to|priv      |priv_received|branch_recursive                                      |grantor           |grantee               |object_schema|object_name|is_grantable|is_superuser|
-------+----------+----------+-------------+------------------------------------------------------+------------------+----------------------+-------------+-----------+------------+------------+
true   |gpbu44973 |SELECT    |OWNER        |gpbu44973                                            |domainadmin_xxxx  |gpbu44973             |gpbu44973_test|test       |YES         |true        |
true   |gpbu44973 |DELETE    |INDIRECTLY   |domainadmin_xxxx->App-xxx-V-AdmRole-xxxx->gpbu44973  |gpbu26350         |domainadmin_xxxx      |public       |test       |NO          |true        |
true   |gpbu44973 |UPDATE    |INDIRECTLY   |domainadmin_xxxx->App-xxx-V-AdmRole-xxxx->gpbu44973  |gpbu26350         |domainadmin_xxxx      |public       |test       |NO          |true        |
```

##### Пример 5: Анализ дерева ролей (без объектов)

```sql
-- Только дерево наследования ролей для gpbu44973
SELECT * FROM adm.get_membership_tree_all('gpbu44973','%','несуществующая123');
```

**Результат:**
```
is_user|granted_to|priv|priv_received|branch_recursive                                   |grantor|grantee|object_schema|object_name|is_grantable|is_superuser|
-------+----------+----+-------------+---------------------------------------------------+-------+-------+-------------+-----------+------------+------------+
true   |gpbu44973 |    |OWNER        |gpbu44973                                          |       |       |             |           |NO          |true        |
true   |gpbu44973 |    |DIRECTLY     |sync_ldap_users->gpbu44973                         |       |       |             |           |NO          |true        |
true   |gpbu44973 |    |DIRECTLY     |App-xxx-V-AdmRole-xxxx->gpbu44973                  |       |       |             |           |NO          |true        |
true   |gpbu44973 |    |INDIRECTLY   |sync_ldap_groups->App-xxx-V-Admins->gpbu44973      |       |       |             |           |NO          |true        |
```

#### 🛠️ Вспомогательные функции для DBA

##### Поиск объектов с правами доступа

```sql
-- Создание функции для поиска объектов с правами доступа
CREATE OR REPLACE FUNCTION adm.get_objects_by_role(role_name text)
RETURNS TABLE(schema text, object text, type text) AS $$
-- v.1.0.0 @sqlmaster
DECLARE
    role_exists boolean;
BEGIN
    -- Проверка существования роли
    SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname = role_name) INTO role_exists;
    IF NOT role_exists THEN
        RAISE EXCEPTION 'Role not found';
    END IF;
    
    -- Возврат объектов с правами доступа
    RETURN QUERY
    SELECT n.nspname::text AS schema,
           c.relname::text AS object,
           CASE c.relkind 
               WHEN 'r' THEN 'table'
               WHEN 'v' THEN 'view' 
               WHEN 'm' THEN 'matview'
               WHEN 'S' THEN 'sequence'
               WHEN 'f' THEN 'foreign table'
           END::text AS type
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    JOIN pg_authid a ON a.oid = c.relowner
    WHERE c.relkind IN ('r', 'v', 'm', 'S', 'f')
      AND a.rolname = role_name
    UNION ALL
    SELECT n.nspname::text,
           p.proname::text, 
           'function'::text
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
    JOIN pg_authid a ON a.oid = p.proowner
    WHERE a.rolname = role_name
    ORDER BY 1, 2;
END;
$$ LANGUAGE plpgsql;
```

##### Поиск объектов во владении

```sql
-- Создание функции для поиска объектов во владении
CREATE OR REPLACE FUNCTION adm.get_objects_owned_by_role(role_name text)
RETURNS TABLE(schema text, object text, type text) AS $$
-- v.1.0.0 @sqlmaster  
DECLARE
    role_exists boolean;
BEGIN
    -- Проверка существования роли
    SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname = role_name) INTO role_exists;
    IF NOT role_exists THEN
        RAISE EXCEPTION 'Role not found';
    END IF;
    
    -- Возврат объектов во владении
    RETURN QUERY
    SELECT n.nspname::text AS schema,
           c.relname::text AS object, 
           CASE c.relkind
               WHEN 'r' THEN 'table'
               WHEN 'v' THEN 'view'
               WHEN 'm' THEN 'matview'
               WHEN 'S' THEN 'sequence'
               WHEN 'f' THEN 'foreign table'
           END::text AS type
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    JOIN pg_authid a ON a.oid = c.relowner
    WHERE c.relkind IN ('r', 'v', 'm', 'S', 'f')
      AND a.rolname = role_name
    UNION ALL
    SELECT n.nspname::text,
           p.proname::text,
           'function'::text
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace  
    JOIN pg_authid a ON a.oid = p.proowner
    WHERE a.rolname = role_name
    ORDER BY 1, 2;
END;
$$ LANGUAGE plpgsql;
```

#### Настройка psql для оперативной работы

Добавьте в `~/.psqlrc`:

```sql
-- Настройка переменных для быстрого анализа привилегий
\set role '%'
\set schema '%'
\set object '%'

-- Алиасы для частых операций
\set dp 'SELECT * FROM adm.get_objects_by_role(:''role'');'      -- Display Privileges
\set do 'SELECT * FROM adm.get_objects_owned_by_role(:''role'');' -- Display Owned
\set r 'SELECT * FROM adm.get_membership_tree_all(:''role'', :''schema'', :''object'');'  -- Role analysis
\set rt 'SELECT * FROM adm.get_membership_tree_all(:''role'', ''%'', ''несуществующая123'');'  -- Role tree only
```

**Пример использования в psql:**
```sql
-- Установить роль для анализа
adb=# \set role roletest

-- Показать дерево наследования ролей
adb=# :rt

-- Показать все привилегии роли
adb=# :r

-- Показать объекты во владении
adb=# :do

-- Показать объекты с правами доступа  
adb=# :dp
```

#### Практические сценарии для Senior DBA

##### Аудит безопасности
```sql
-- Поиск избыточных привилегий
SELECT granted_to, COUNT(*) as privilege_count
FROM adm.get_membership_tree_all('app_%')
WHERE priv IS NOT NULL
GROUP BY granted_to
HAVING COUNT(*) > 50;
```

##### Анализ инцидентов
```sql
-- Полная карта доступа скомпрометированного пользователя
SELECT * FROM adm.get_membership_tree_all('compromised_user')
WHERE object_schema NOT LIKE 'pg_%'
ORDER BY priv_received, object_schema;
```

##### Подготовка к миграции
```sql
-- Анализ зависимостей перед удалением роли
SELECT DISTINCT granted_to, branch_recursive
FROM adm.get_membership_tree_all('deprecated_role')
WHERE priv_received != 'OWNER';
```

---

**Итог**: Функция `adm.get_membership_tree_all` превращает сложный анализ привилегий PostgreSQL из рутинной работы в эффективный инструмент безопасности, необходимый каждому Senior DBA в enterprise-средах.
