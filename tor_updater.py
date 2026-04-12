"""Atualizador local da lista de Tor exit nodes."""

import argparse

from advanced_analysis import (
    TOR_CACHE_TTL_HOURS,
    get_tor_exit_cache_status,
    update_tor_exit_nodes_cache,
)


def main():
    parser = argparse.ArgumentParser(
        description='Atualiza localmente o cache de Tor exit nodes usando torbulkexitlist + Onionoo.'
    )
    parser.add_argument('--cache-file', default='tor_exit_nodes.json', help='Arquivo JSON de cache.')
    parser.add_argument('--ttl-hours', type=float, default=TOR_CACHE_TTL_HOURS,
                        help='TTL considerado ao usar --skip-if-fresh.')
    parser.add_argument('--skip-if-fresh', action='store_true',
                        help='Não atualiza se o cache ainda estiver dentro do TTL.')
    args = parser.parse_args()

    if args.skip_if_fresh:
        status = get_tor_exit_cache_status(cache_file=args.cache_file, ttl_hours=args.ttl_hours)
        if status.get('available') and not status.get('is_stale'):
            age_hours = status.get('age_hours', 0)
            node_count = status.get('node_count', 0)
            print(f'Lista Tor já está atual: {node_count} IPs, idade {age_hours:.1f}h.')
            return 0

    result = update_tor_exit_nodes_cache(cache_file=args.cache_file)
    if result.get('success'):
        print(f"Lista Tor atualizada com {result['node_count']} IPs únicos.")
        print(f"torbulkexitlist: {result['source_counts'].get('torbulkexitlist', 0)}")
        print(f"Onionoo: {result['source_counts'].get('onionoo', 0)}")
        for source, error in result.get('source_errors', {}).items():
            print(f"Aviso {source}: {error}")
        return 0

    print(result.get('error', 'Falha ao atualizar lista Tor.'))
    for source, error in result.get('source_errors', {}).items():
        print(f"{source}: {error}")
    return 1


if __name__ == '__main__':
    raise SystemExit(main())