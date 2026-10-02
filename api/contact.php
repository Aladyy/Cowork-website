<?php
/**
 * Proteck — traitement des formulaires de rappel / contact.
 * Reçoit le POST des formulaires du site et envoie la demande par e-mail.
 *
 * - Répond en JSON si la requête le demande (envoi AJAX), sinon redirige vers /merci/.
 * - Anti-spam : champ piège, délai minimal de remplissage, limitation du nombre d'envois par IP.
 * - Aucune donnée personnelle n'est stockée sur le serveur (seule une empreinte d'IP est gardée 1 h).
 *
 * Réglages : api/config.php
 */

declare(strict_types=1);

$config = require __DIR__ . '/config.php';

$wantsJson = str_contains($_SERVER['HTTP_ACCEPT'] ?? '', 'application/json');

/* ------------------------------------------------------------------ réponses */
function respond(bool $ok, string $message, int $status, bool $json): never
{
    http_response_code($status);
    header('X-Content-Type-Options: nosniff');
    header('Cache-Control: no-store');
    if ($json) {
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['ok' => $ok, 'message' => $message], JSON_UNESCAPED_UNICODE);
        exit;
    }
    if ($ok) {
        header('Location: /merci/', true, 303);
        exit;
    }
    header('Content-Type: text/html; charset=utf-8');
    $msg = htmlspecialchars($message, ENT_QUOTES, 'UTF-8');
    echo <<<HTML
<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex"><title>Le message n’est pas parti | Proteck</title>
<style>body{font-family:system-ui,sans-serif;max-width:40rem;margin:4rem auto;padding:0 1rem;color:#111627;line-height:1.6}
a{color:#111627;text-decoration-color:#FCB128;text-decoration-thickness:2px}</style></head>
<body><h1>Le message n’est pas parti</h1><p>{$msg}</p>
<p><a href="javascript:history.back()">Revenir au formulaire</a> ou appelez-nous au <a href="tel:+33565341064">05 65 34 10 64</a>.</p></body></html>
HTML;
    exit;
}

/* ------------------------------------------------------------------ méthode */
if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    header('Allow: POST');
    respond(false, 'Méthode non autorisée.', 405, $wantsJson);
}

/* ------------------------------------------------------------------ lecture */
function field(string $name, int $max): string
{
    $v = $_POST[$name] ?? '';
    if (!is_string($v)) {
        return '';
    }
    $v = trim(str_replace("\0", '', $v));
    return mb_substr($v, 0, $max, 'UTF-8');
}
function oneLine(string $v): string
{
    return trim(preg_replace('/[\r\n\t]+/', ' ', $v) ?? '');
}

$nom        = oneLine(field('nom', 120));
$telephone  = oneLine(field('telephone', 30));
$email      = oneLine(field('email', 160));
$societe    = oneLine(field('societe', 120));
$objet      = field('objet', 20);
$message    = field('message', 3000);
$page       = oneLine(field('page', 200));
$formulaire = field('formulaire', 20) === 'contact' ? 'contact' : 'rappel';
$piege      = field('site_web', 200);
$t          = field('t', 20);

$objets = [
    'rappel'  => 'Demande de rappel',
    'audit'   => 'Demande d’audit cyber offert',
    'devis'   => 'Demande de devis',
    'urgence' => 'URGENCE : panne ou cyberattaque',
    'autre'   => 'Autre question',
];
if (!isset($objets[$objet])) {
    $objet = 'rappel';
}

/* ------------------------------------------------------------------ anti-spam */
// Champ piège rempli → robot. On répond « OK » sans rien envoyer.
if ($piege !== '') {
    respond(true, 'Merci.', 200, $wantsJson);
}
// Formulaire envoyé trop vite (le champ t est rempli par JavaScript au chargement de la page).
if ($t !== '' && ctype_digit($t)) {
    $elapsed = time() - (int) $t;
    if ($elapsed < $config['min_seconds']) {
        respond(true, 'Merci.', 200, $wantsJson);
    }
}
// Limitation : N envois réussis par heure et par adresse IP (empreinte salée, jamais l'IP en clair).
// Seuls les envois valides sont comptés : une erreur de saisie ne pénalise pas le visiteur.
$dataDir = $config['data_dir'];
if (!is_dir($dataDir)) {
    @mkdir($dataDir, 0750, true);
}
$rateFile = $dataDir . '/limites.json';
$ipHash = hash('sha256', ($config['salt'] ?: __FILE__) . ($_SERVER['REMOTE_ADDR'] ?? ''));

/** Lit/écrit le fichier de limitation sous verrou. $record = true pour compter un envoi. Retourne false si la limite est atteinte. */
function rateLimit(string $file, string $key, int $max, bool $record): bool
{
    $fp = @fopen($file, 'c+');
    if (!$fp) {
        return true; // pas de fichier possible : on ne bloque pas les vrais clients
    }
    flock($fp, LOCK_EX);
    $now = time();
    $hits = json_decode(stream_get_contents($fp) ?: '{}', true) ?: [];
    foreach ($hits as $k => $times) {
        $hits[$k] = array_values(array_filter((array) $times, fn($ts) => $now - (int) $ts < 3600));
        if (!$hits[$k]) {
            unset($hits[$k]);
        }
    }
    $ok = count($hits[$key] ?? []) < $max;
    if ($ok && $record) {
        $hits[$key][] = $now;
    }
    ftruncate($fp, 0);
    rewind($fp);
    fwrite($fp, json_encode($hits));
    fflush($fp);
    flock($fp, LOCK_UN);
    fclose($fp);
    return $ok;
}

if (!rateLimit($rateFile, $ipHash, (int) $config['max_per_hour'], false)) {
    respond(false, 'Vous avez envoyé plusieurs demandes en peu de temps. Merci de patienter ou de nous appeler.', 429, $wantsJson);
}

/* ------------------------------------------------------------------ validation */
$erreurs = [];
if (mb_strlen($nom, 'UTF-8') < 2) {
    $erreurs[] = 'Indiquez votre nom.';
}
$chiffres = preg_replace('/\D/', '', $telephone) ?? '';
if (strlen($chiffres) < 10 || !preg_match('/^[0-9+().\s-]+$/', $telephone)) {
    $erreurs[] = 'Indiquez un numéro de téléphone valide.';
}
if ($email !== '' && !filter_var($email, FILTER_VALIDATE_EMAIL)) {
    $erreurs[] = 'L’adresse e-mail n’est pas valide.';
}
if ($formulaire === 'contact') {
    if ($email === '') {
        $erreurs[] = 'Indiquez votre adresse e-mail.';
    }
    if (mb_strlen($message, 'UTF-8') < 5) {
        $erreurs[] = 'Décrivez votre demande en quelques mots.';
    }
}
// Trop de liens dans le message → spam quasi certain
if (preg_match_all('#https?://#i', $message) > 3) {
    $erreurs[] = 'Votre message contient trop de liens.';
}
if ($erreurs) {
    respond(false, implode(' ', $erreurs), 422, $wantsJson);
}

/* ------------------------------------------------------------------ e-mail */
rateLimit($rateFile, $ipHash, (int) $config['max_per_hour'], true);

$sujet = sprintf('[Site web] %s : %s%s', $objets[$objet], $nom, $societe !== '' ? " ($societe)" : '');
$date = (new DateTimeImmutable('now', new DateTimeZone('Europe/Paris')))->format('d/m/Y à H:i');

$corps = implode("\n", [
    $objets[$objet],
    str_repeat('-', 40),
    'Nom       : ' . $nom,
    'Téléphone : ' . $telephone,
    'E-mail    : ' . ($email !== '' ? $email : '(non renseigné)'),
    'Société   : ' . ($societe !== '' ? $societe : '(non renseignée)'),
    '',
    'Message :',
    $message !== '' ? $message : '(aucun message)',
    '',
    str_repeat('-', 40),
    'Envoyé le ' . $date . ' depuis la page ' . ($page !== '' ? $page : '/') . ' (formulaire « ' . $formulaire . ' »).',
]);

$encode = fn(string $s): string => '=?UTF-8?B?' . base64_encode($s) . '?=';
$headers = [
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=UTF-8',
    'Content-Transfer-Encoding: 8bit',
    'From: ' . $encode($config['from_name']) . ' <' . $config['from_email'] . '>',
    'X-Mailer: Proteck-site',
];
if ($email !== '') {
    $headers[] = 'Reply-To: ' . $encode($nom) . ' <' . $email . '>';
}
if ($objet === 'urgence') {
    $headers[] = 'X-Priority: 1 (Highest)';
    $headers[] = 'Importance: High';
}

$envoye = @mail(
    implode(', ', $config['to']),
    $encode($sujet),
    $corps,
    implode("\r\n", $headers),
    $config['envelope_sender'] !== '' ? '-f' . $config['envelope_sender'] : ''
);

if (!$envoye) {
    error_log('[proteck-contact] échec de mail() pour une demande « ' . $objet . ' »');
    respond(false, 'Le serveur n’a pas pu transmettre votre message.', 500, $wantsJson);
}

respond(true, 'Merci, votre demande est bien envoyée.', 200, $wantsJson);
