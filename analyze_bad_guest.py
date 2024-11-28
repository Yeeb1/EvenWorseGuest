import json
import argparse
from collections import defaultdict

def main():
    parser = argparse.ArgumentParser(description='Parse Azure AD JSON data and generate statistics.')
    parser.add_argument('json_file', metavar='JSON_FILE', type=str, nargs='?',
                        default='bh.json',
                        help='The JSON file to parse (default: bh.json)')
    args = parser.parse_args()

    json_file = args.json_file

    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"Error: File '{json_file}' not found.")
        return
    except json.JSONDecodeError as e:
        print(f"Error: Failed to parse JSON file '{json_file}': {e}")
        return

    users = {}
    groups = {}
    group_membership = defaultdict(list)  # key: groupId, value: list of member userIds
    user_groups = defaultdict(list)       # key: userId, value: list of groupIds

    for item in data.get('data', []):
        kind = item.get('kind')
        item_data = item.get('data')

        if kind == 'AZUser':
            user_id = item_data.get('id')
            users[user_id] = {
                'id': user_id,
                'displayName': item_data.get('displayName'),
                'userPrincipalName': item_data.get('userPrincipalName'),
                'mail': item_data.get('mail'),
                'userType': item_data.get('userType')
            }

        elif kind == 'AZGroup':
            group_id = item_data.get('id')
            groups[group_id] = {
                'id': group_id,
                'displayName': item_data.get('displayName'),
                'description': item_data.get('description'),
                'mail': item_data.get('mail')
            }

        elif kind == 'AZGroupMember':
            group_id = item_data.get('groupId')
            members = item_data.get('members', [])
            for member_info in members:
                member = member_info.get('member', {})
                user_id = member.get('id')
                if user_id:
                    group_membership[group_id].append(user_id)
                    user_groups[user_id].append(group_id)


    # 1. Which user is in the most groups?
    user_group_counts = {user_id: len(group_ids) for user_id, group_ids in user_groups.items()}
    max_groups = max(user_group_counts.values()) if user_group_counts else 0
    users_in_most_groups = [user_id for user_id, count in user_group_counts.items() if count == max_groups]

    print(f"\n{'='*60}")
    print(f"User(s) in the most groups ({max_groups} groups):")
    print(f"{'='*60}")
    for user_id in users_in_most_groups:
        user_info = users.get(user_id, {})
        print(f"- {user_info.get('displayName')} ({user_info.get('userPrincipalName')})")

    # 2. Which group has the most members?
    group_member_counts = {group_id: len(user_ids) for group_id, user_ids in group_membership.items()}
    max_members = max(group_member_counts.values()) if group_member_counts else 0
    groups_with_most_members = [group_id for group_id, count in group_member_counts.items() if count == max_members]

    print(f"\n{'='*60}")
    print(f"Group(s) with the most members ({max_members} members):")
    print(f"{'='*60}")
    for group_id in groups_with_most_members:
        group_info = groups.get(group_id, {})
        print(f"- {group_info.get('displayName')}")

    # 3. Total number of users and groups
    total_users = len(users)
    total_groups = len(groups)

    print(f"\n{'='*60}")
    print(f"Total number of users: {total_users}")
    print(f"Total number of groups: {total_groups}")
    print(f"{'='*60}")

    # 4. Average number of groups per user
    average_groups_per_user = (sum(user_group_counts.values()) / total_users) if total_users > 0 else 0
    print(f"Average number of groups per user: {average_groups_per_user:.2f}")

    # 5. Average number of members per group
    average_members_per_group = (sum(group_member_counts.values()) / total_groups) if total_groups > 0 else 0
    print(f"Average number of members per group: {average_members_per_group:.2f}")

    # 6. List top 5 users in terms of group memberships
    top_n = 5
    sorted_users_by_groups = sorted(user_group_counts.items(), key=lambda x: x[1], reverse=True)
    print(f"\n{'='*60}")
    print(f"Top {top_n} users by number of group memberships:")
    print(f"{'='*60}")
    for user_id, count in sorted_users_by_groups[:top_n]:
        user_info = users.get(user_id, {})
        print(f"- {user_info.get('displayName')} ({user_info.get('userPrincipalName')}): {count} groups")

    # 7. List top 5 groups by number of members
    sorted_groups_by_members = sorted(group_member_counts.items(), key=lambda x: x[1], reverse=True)
    print(f"\n{'='*60}")
    print(f"Top {top_n} groups by number of members:")
    print(f"{'='*60}")
    for group_id, count in sorted_groups_by_members[:top_n]:
        group_info = groups.get(group_id, {})
        print(f"- {group_info.get('displayName')}: {count} members")

    # 8. Print group memberships for the top 5 users
    print(f"\n{'='*60}")
    print(f"Group memberships for the top {top_n} users:")
    print(f"{'='*60}")
    for user_id, count in sorted_users_by_groups[:top_n]:
        user_info = users.get(user_id, {})
        group_ids = user_groups.get(user_id, [])
        group_names = [groups[group_id]['displayName'] for group_id in group_ids if group_id in groups]
        print(f"\n{user_info.get('displayName')} ({user_info.get('userPrincipalName')}):")
        for group_name in group_names:
            print(f"  - {group_name}")

    # 9. Save user and group relationships into a JSON file, which is easier to parse and work with.
    relationship_data = {
        'users': users,
        'groups': groups,
        'userGroups': user_groups,            # userId -> list of groupIds
        'groupMembers': group_membership      # groupId -> list of userIds
    }

    output_filename = 'user_group_relationships.json'
    try:
        with open(output_filename, 'w', encoding='utf-8') as f:
            json.dump(relationship_data, f, indent=4)
        print(f"\n{'='*60}")
        print(f"User and group relationships have been saved to '{output_filename}'.")
        print(f"{'='*60}")
    except Exception as e:
        print(f"Error: Failed to write to file '{output_filename}': {e}")

if __name__ == '__main__':
    main()
