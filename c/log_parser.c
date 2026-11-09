/*
 * ============================================================
 * DIGITAL CRIME SCENE
 * Projekt: Server-Log-Analyse
 * Programmiersprache: C
 * Datei: log_parser.c
 *
 * Aufgabe:
 * 1. Eine Logdatei öffnen.
 * 2. Die Datei Zeile für Zeile einlesen.
 * 3. Nur LOGIN_FAILED-Ereignisse untersuchen.
 * 4. IPv4-Adressen überprüfen.
 * 5. Fehlversuche pro IP-Adresse zählen.
 * 6. Die Ergebnisse ausgeben.
 *
 * Erwartetes Logformat:
 * ZEITSTEMPEL|EREIGNIS|BENUTZER|IP-ADRESSE|ZUSATZFELD
 *
 * Beispiel:
 * 2026-10-30 02:14:03|LOGIN_FAILED|user123|192.168.1.50|-
 * ============================================================
 */

#include <stdio.h>   // printf, fprintf, fopen, fgets, fclose
#include <string.h>  // strcmp, strtok, strcspn, strchr
#include <limits.h>  // INT_MAX

/* ------------------------------------------------------------
 * 1. KONSTANTEN
 * ------------------------------------------------------------ */

/* Maximale Anzahl unterschiedlicher IP-Adressen. */
#define MAX_IPS 100

/* Größe des Puffers für eine Logzeile. */
#define MAX_LENGTH 512

/* Größe des Speicherplatzes für eine IP-Adresse. */
#define IP_LENGTH 50

/* Ab diesem Wert melden wir eine IP als auffaellig. */
#define ALERT_THRESHOLD 3

/* ------------------------------------------------------------
 * 2. DATENSTRUKTUR
 * ------------------------------------------------------------ */

/*
 * Ein IPData-Eintrag speichert zwei zusammengehörige Werte:
 * - ip: die IP-Adresse
 * - failed_logins: Anzahl fehlgeschlagener Logins dieser IP
 */
typedef struct {
    char ip[IP_LENGTH];
    int failed_logins;
} IPData;

/* ------------------------------------------------------------
 * 3. LOGDATEI ÖFFNEN
 * ------------------------------------------------------------ */

/*
 * Öffnet die angegebene Datei im Lesemodus.
 *
 * filename: Pfad zur Logdatei
 *
 * Rückgabe:
 * - FILE-Zeiger, wenn das Öffnen erfolgreich war
 * - NULL, wenn ein Fehler aufgetreten ist
 */
FILE *open_log_file(const char *filename)
{
    FILE *file = fopen(filename, "r");

    if (file == NULL) {
        perror("Fehler beim Öffnen der Logdatei");
        return NULL;
    }

    return file;
}

/* ------------------------------------------------------------
 * 4. IP-ADRESSE IM ARRAY SUCHEN
 * ------------------------------------------------------------ */

/*
 * Durchsucht alle bereits verwendeten Array-Einträge.
 *
 * ips:      Array mit gespeicherten IPData-Einträgen
 * ip_count: Anzahl der tatsächlich verwendeten Einträge
 * ip:       IP-Adresse, nach der gesucht wird
 *
 * Rückgabe:
 * - Index 0, 1, 2, ... wenn die IP gefunden wurde
 * -1, wenn die IP noch nicht gespeichert ist
 */
int find_ip(IPData ips[], int ip_count, const char *ip)
{
    for (int i = 0; i < ip_count; i++) {
        /*
         * strcmp liefert 0, wenn beide Zeichenketten gleich sind.
         */
        if (strcmp(ips[i].ip, ip) == 0) {
            return i;
        }
    }

    return -1;
}

/* ------------------------------------------------------------
 * 5. IPv4-ADRESSE VALIDIEREN
 * ------------------------------------------------------------ */

/*
 * Prüft das Format einer IPv4-Adresse.
 *
 * Gültige Beispiele:
 * - 192.168.1.50
 * - 10.0.0.5
 * - 8.8.8.8
 *
 * Ungültige Beispiele:
 * - 999.1.1.1
 * - 192.168.1
 * - 192.168.1.999
 * - abc.def.ghi.jkl
 *
 * Rückgabe:
 * 1 = gültig
 * 0 = ungültig
 *
 * Diese Funktion prüft die IPv4-Schreibweise. Sie prüft nicht,
 * ob die Adresse in einem Netzwerk tatsächlich erreichbar ist.
 */
int is_valid_ip(const char *ip)
{
    if (ip == NULL) {
        return 0;
    }

    const char *p = ip;

    /* Eine IPv4-Adresse besteht aus genau vier Zahlenblöcken. */
    for (int octet = 0; octet < 4; octet++) {
        int value = 0;
        int digits = 0;

        /* Jeder Zahlenblock muss mit einer Ziffer beginnen. */
        if (*p < '0' || *p > '9') {
            return 0;
        }

        /* Mehrstellige Zahlenblöcke dürfen nicht mit 0 beginnen. */
        if (*p == '0' && p[1] >= '0' && p[1] <= '9') {
            return 0;
        }

        /* Ziffern des aktuellen Zahlenblocks verarbeiten. */
        while (*p >= '0' && *p <= '9') {
            /* Ein IPv4-Zahlenblock hat höchstens drei Ziffern. */
            if (digits >= 3) {
                return 0;
            }

            /*
             * Zeichen in Zahl umwandeln:
             * '0' bis '9' werden zu 0 bis 9.
             *
             * Beispiel: Aus 19 und der Ziffer '2' wird 192.
             */
            value = value * 10 + (*p - '0');

            /* Jeder Zahlenblock muss zwischen 0 und 255 liegen. */
            if (value > 255) {
                return 0;
            }

            digits++;
            p++;
        }

        if (digits == 0) {
            return 0;
        }

        /* Zwischen den ersten drei Zahlenblöcken muss ein Punkt stehen. */
        if (octet < 3) {
            if (*p != '.') {
                return 0;
            }

            p++; /* Punkt überspringen. */
        } else {
            /* Nach dem vierten Zahlenblock darf nichts mehr folgen. */
            if (*p != '\0') {
                return 0;
            }
        }
    }

    return 1;
}

/* ------------------------------------------------------------
 * 6. IP SPEICHERN ODER ZÄHLER ERHÖHEN
 * ------------------------------------------------------------ */

/*
 * Ist die IP bereits vorhanden, wird ihr Zähler erhöht.
 * Ist sie neu, wird ein neuer Array-Eintrag angelegt.
 *
 * ip_count ist ein Zeiger, damit diese Funktion den Wert der
 * Variablen aus main() verändern kann.
 *
 * Rückgabe:
 * 1 = erfolgreich verarbeitet
 * 0 = Verarbeitung nicht möglich
 */
int update_ip(IPData ips[], int *ip_count, const char *ip)
{
    if (ips == NULL || ip_count == NULL || ip == NULL) {
        return 0;
    }

    /* Zuerst prüfen, ob diese IP bereits gespeichert ist. */
    int index = find_ip(ips, *ip_count, ip);

    if (index != -1) {
        /*
         * Die IP ist bereits vorhanden.
         * Prüfen, ob der int-Zähler noch erhöht werden kann.
         */
        if (ips[index].failed_logins == INT_MAX) {
            fprintf(stderr,
                    "WARNUNG: Loginzaehler fuer %s ist voll.\n",
                    ip);
            return 0;
        }

        /* Vorhandenen Zähler um eins erhöhen. */
        ips[index].failed_logins++;

        return 1;
    }

    /* Die IP ist neu: Prüfen, ob das Array noch Platz hat. */
    if (*ip_count >= MAX_IPS) {
        fprintf(stderr,
                "WARNUNG: Maximale Anzahl an IP-Adressen erreicht.\n");
        return 0;
    }

    /*
     * Die IP in den nächsten freien Array-Eintrag kopieren.
     * snprintf begrenzt die Anzahl der geschriebenen Zeichen.
     */
    int written = snprintf(ips[*ip_count].ip,
                           sizeof(ips[*ip_count].ip),
                           "%s",
                           ip);

    if (written < 0 ||
        (size_t)written >= sizeof(ips[*ip_count].ip)) {
        return 0;
    }

    /* Der erste fehlgeschlagene Login ergibt den Startwert 1. */
    ips[*ip_count].failed_logins = 1;

    /* Jetzt ist ein weiterer Array-Eintrag belegt. */
    (*ip_count)++;

    return 1;
}

/* ------------------------------------------------------------
 * 7. EINZELNE LOGZEILE VERARBEITEN
 * ------------------------------------------------------------ */

/*
 * Zerlegt eine Logzeile anhand des Trennzeichens '|'.
 *
 * Erwartetes Format:
 * ZEITSTEMPEL|EREIGNIS|BENUTZER|IP-ADRESSE|ZUSATZFELD
 *
 * Rückgabe:
 * 1 = ein fehlgeschlagener Login wurde verarbeitet
 * 0 = die Zeile wurde übersprungen oder nicht gezählt
 */
int process_log_line(char *line, IPData ips[], int *ip_count)
{
    if (line == NULL || ips == NULL || ip_count == NULL) {
        return 0;
    }

    /* Zeilenumbruch am Ende entfernen. */
    line[strcspn(line, "\r\n")] = '\0';

    /* Leere Zeilen überspringen. */
    if (line[0] == '\0') {
        return 0;
    }

    /*
     * strtok zerlegt die Zeile an '|'.
     * Achtung: strtok verändert dabei den Inhalt von line.
     */
    char *timestamp = strtok(line, "|");
    char *event     = strtok(NULL, "|");
    char *user      = strtok(NULL, "|");
    char *ip        = strtok(NULL, "|");
    char *extra     = strtok(NULL, "|");

    /* Wir erwarten fünf Felder. */
    if (timestamp == NULL ||
        event == NULL ||
        user == NULL ||
        ip == NULL ||
        extra == NULL) {
        fprintf(stderr, "WARNUNG: Unvollstaendige Logzeile uebersprungen.\n");
        return 0;
    }

    /* Nur LOGIN_FAILED-Ereignisse zählen. */
    if (strcmp(event, "LOGIN_FAILED") != 0) {
        return 0;
    }

    /* IP-Adresse auf gültige IPv4-Schreibweise prüfen. */
    if (!is_valid_ip(ip)) {
        fprintf(stderr, "WARNUNG: Ungueltige IP-Adresse: %s\n", ip);
        return 0;
    }

    /* IP speichern oder den vorhandenen Zähler erhöhen. */
    return update_ip(ips, ip_count, ip);
}

/* ------------------------------------------------------------
 * 8. GESAMTE LOGDATEI VERARBEITEN
 * ------------------------------------------------------------ */

/*
 * Liest die Datei Zeile für Zeile und übergibt jede Zeile
 * an process_log_line().
 *
 * Rückgabe:
 * 1 = Datei ohne Lesefehler verarbeitet
 * 0 = ungültige Argumente oder Lesefehler
 */
int process_log_file(FILE *file, IPData ips[], int *ip_count)
{
    if (file == NULL || ips == NULL || ip_count == NULL) {
        return 0;
    }

    char line[MAX_LENGTH];

    while (fgets(line, sizeof(line), file) != NULL) {
        /*
         * Prüfen, ob fgets einen Zeilenumbruch gelesen hat.
         * Wenn nicht, lesen wir ein weiteres Zeichen:
         *
         * - EOF: Es war die letzte, möglicherweise nicht mit
         *   newline abgeschlossene Zeile. Sie ist trotzdem gültig.
         * - newline: Die Zeile passte genau in den Puffer.
         * - anderes Zeichen: Die Zeile ist zu lang.
         */
        if (strchr(line, '\n') == NULL) {
            int next_char = fgetc(file);

            if (next_char != EOF && next_char != '\n') {
                fprintf(stderr,
                        "WARNUNG: Logzeile ist zu lang und wird uebersprungen.\n");

                /* Rest der überlangen Zeile verwerfen. */
                while (next_char != '\n' && next_char != EOF) {
                    next_char = fgetc(file);
                }

                continue;
            }
        }

        /* Die eingelesene Zeile analysieren. */
        process_log_line(line, ips, ip_count);
    }

    /* Prüfen, ob beim Lesen ein Fehler aufgetreten ist. */
    if (ferror(file)) {
        perror("Fehler beim Lesen der Logdatei");
        return 0;
    }

    return 1;
}

/* ------------------------------------------------------------
 * 9. ERGEBNISSE AUSGEBEN
 * ------------------------------------------------------------ */

/*
 * Gibt jede gefundene IP-Adresse und ihren Zähler aus.
 *
 * Das Format IP|ANZAHL kann später leicht von Python
 * weiterverarbeitet werden.
 */
void print_results(const IPData ips[], int ip_count)
{
    printf("\nSECURITY ANALYSIS RESULTS\n");
    printf("------------------------------\n");

    if (ip_count == 0) {
        printf("Keine fehlgeschlagenen Logins gefunden.\n");
    } else {
        printf("IP-Adresse|Fehlgeschlagene_Logins\n");

        for (int i = 0; i < ip_count; i++) {
            printf("%s|%d\n",
                   ips[i].ip,
                   ips[i].failed_logins);
        }
    }

    printf("------------------------------\n");
}


/* ------------------------------------------------------------
 * 10. SICHERHEITSWARNUNGEN AUSGEBEN
 * ------------------------------------------------------------ */

/*
 * Meldet alle IP-Adressen, deren Anzahl fehlgeschlagener Logins
 * mindestens ALERT_THRESHOLD erreicht.
 *
 * Das ist eine einfache Heuristik und noch kein Beweis fuer
 * einen Angriff. Der Schwellenwert kann spaeter angepasst werden.
 */
void print_security_alerts(const IPData ips[], int ip_count)
{
    int alert_count = 0;

    printf("\nSECURITY ALERTS\n");
    printf("------------------------------\n");

    for (int i = 0; i < ip_count; i++) {
        if (ips[i].failed_logins >= ALERT_THRESHOLD) {
            printf("VERDACHT: IP %s hat %d fehlgeschlagene Logins.\n",
                   ips[i].ip,
                   ips[i].failed_logins);
            alert_count++;
        }
    }

    if (alert_count == 0) {
        printf("Keine IP hat den Schwellenwert von %d erreicht.\n",
               ALERT_THRESHOLD);
    } else {
        printf("Anzahl auffaelliger IP-Adressen: %d\n", alert_count);
    }

    printf("------------------------------\n");
}

/* ------------------------------------------------------------
 * 11. HAUPTFUNKTION
 * ------------------------------------------------------------ */

/*
 * argc: Anzahl der Kommandozeilenargumente
 * argv: Array mit den Argumenten
 *
 * Aufruf:
 * ./bin/log_parser data/server_logs.txt
 *
 * argv[0] ist der Programmname.
 * argv[1] ist der Pfad zur Logdatei.
 */
int main(int argc, char *argv[])
{
    /* Es muss genau ein Dateipfad angegeben werden. */
    if (argc != 2) {
        fprintf(stderr,
                "Verwendung: %s <logdatei>\n",
                argv[0]);
        return 1;
    }

    /* Logdatei öffnen. */
    FILE *file = open_log_file(argv[1]);

    if (file == NULL) {
        return 1;
    }

    /* Array für die unterschiedlichen IP-Adressen anlegen. */
    IPData ips[MAX_IPS];

    /* Zu Beginn wurde noch keine IP-Adresse gespeichert. */
    int ip_count = 0;

    /* Logdatei analysieren. */
    int success = process_log_file(file, ips, &ip_count);

    /* Datei immer nach der Verarbeitung schließen. */
    if (fclose(file) == EOF) {
        perror("Fehler beim Schliessen der Logdatei");
        return 1;
    }

    /* Bei einem Lesefehler keine normalen Ergebnisse ausgeben. */
    if (!success) {
        return 1;
    }

    /* Analyseergebnisse ausgeben. */
    print_results(ips, ip_count);

    /* Zusaetzlich auffaellige IP-Adressen melden. */
    print_security_alerts(ips, ip_count);

    /* Rückgabewert 0 bedeutet: Programm erfolgreich beendet. */
    return 0;
}
