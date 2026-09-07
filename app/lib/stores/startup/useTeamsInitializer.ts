import { useEffect } from 'react';
import { convexTeamsStore, type ConvexTeam } from '~/lib/stores/convexTeams';
import { getConvexAuthToken, waitForConvexSessionId } from '~/lib/stores/sessionId';
import { getStoredTeamSlug, setSelectedTeamSlug } from '~/lib/stores/convexTeams';
import { toast } from 'sonner';
import type { ConvexReactClient } from 'convex/react';
import { useConvex, useQuery } from 'convex/react';
import { api } from '@convex/_generated/api';
import { VITE_PROVISION_HOST } from '~/lib/convexProvisionHost';

export function useTeamsInitializer() {
  const convex = useConvex();
  const localProvisioning = useQuery(api.convexProjects.isLocalProvisioningEnabled);
  useEffect(() => {
    if (localProvisioning) {
      // Fork 3b.2 — deployment-per-app: there are no hosted Convex teams. Seed
      // a synthetic "local" team so the chat/usage code paths that read
      // selectedTeamSlug keep working without any api.convex.dev call.
      convexTeamsStore.set([{ id: 'local', name: 'Local Convex', slug: 'local', referralCode: '' }]);
      setSelectedTeamSlug('local');
      return;
    }
    void fetchTeams(convex);
  }, [convex, localProvisioning]);
}

async function fetchTeams(convex: ConvexReactClient) {
  let teams: ConvexTeam[];
  await waitForConvexSessionId('fetchTeams');
  try {
    const token = getConvexAuthToken(convex);
    if (!token) {
      throw new Error('Missing auth token');
    }
    const response = await fetch(`${VITE_PROVISION_HOST}/api/dashboard/teams`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });
    if (!response.ok) {
      const body = await response.text();
      throw new Error(`Failed to fetch teams: ${response.statusText}: ${body}`);
    }
    teams = await response.json();
  } catch (error) {
    console.error('Error fetching teams:', error);
    toast.error('Failed to load user. Try logging in at https://dashboard.convex.dev.');
    return;
  }
  convexTeamsStore.set(teams);
  const teamSlugFromLocalStorage = getStoredTeamSlug();
  if (teamSlugFromLocalStorage) {
    const team = teams.find((team) => team.slug === teamSlugFromLocalStorage);
    if (team) {
      setSelectedTeamSlug(teamSlugFromLocalStorage);
      return;
    }
  }
  if (teams.length === 1) {
    setSelectedTeamSlug(teams[0].slug);
    return;
  }
  // Force the user to select a team.
  setSelectedTeamSlug(null);
}
