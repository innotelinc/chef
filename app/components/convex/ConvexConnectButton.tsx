import { getConvexAuthToken, useConvexSessionId } from '~/lib/stores/sessionId';
import { setSelectedTeamSlug, useSelectedTeamSlug } from '~/lib/stores/convexTeams';
import { useConvex, useQuery } from 'convex/react';
import { api } from '@convex/_generated/api';
import { useChatId } from '~/lib/stores/chatId';
import { TeamSelector } from './TeamSelector';
import { Link1Icon } from '@radix-ui/react-icons';
import { Button } from '@ui/Button';

export function ConvexConnectButton() {
  const convexClient = useConvex();
  const sessionId = useConvexSessionId();
  const chatId = useChatId();
  const credentials = useQuery(api.convexProjects.loadConnectedConvexProjectCredentials, {
    sessionId,
    chatId,
  });
  const localProvisioning = useQuery(api.convexProjects.isLocalProvisioningEnabled);
  const selectedTeamSlug = useSelectedTeamSlug();

  const handleClick = async () => {
    if (localProvisioning) {
      // Fork 3b.2 — deployment-per-app: provision a per-app backend through
      // chef-provisioner; no team/workos token involved.
      if (!sessionId || !chatId) {
        console.error('Missing session or chat');
        return;
      }
      await convexClient.mutation(api.convexProjects.startProvisionLocalProject, {
        sessionId,
        chatId,
      });
      return;
    }
    if (selectedTeamSlug === null) {
      console.error('No team selected');
      return;
    }
    const workosAccessToken = getConvexAuthToken(convexClient);
    if (!workosAccessToken) {
      console.error('No WorkOS access token');
      return;
    }
    await convexClient.mutation(api.convexProjects.startProvisionConvexProject, {
      sessionId,
      chatId,
      projectInitParams: {
        teamSlug: selectedTeamSlug,
        workosAccessToken,
      },
    });
  };
  const isLoading = credentials === undefined || credentials?.kind === 'connecting';

  if (localProvisioning) {
    return (
      <div className="flex flex-col gap-2">
        <p className="mb-2 text-sm text-content-secondary">
          Your Chef app runs on a per-app Convex backend on this host. Connect to provision it.
        </p>
        <div className="flex items-center gap-2">
          <Button
            icon={<Link1Icon />}
            loading={isLoading}
            disabled={isLoading}
            onClick={handleClick}
          >
            {isLoading ? 'Connecting…' : 'Connect to local Convex'}
          </Button>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-2">
      <p className="mb-2 text-sm text-content-secondary">Select a Convex team to connect your Chef app to.</p>
      <div className="flex items-center gap-2">
        <TeamSelector
          selectedTeamSlug={selectedTeamSlug}
          setSelectedTeamSlug={setSelectedTeamSlug}
          description="Your project will be created in this Convex team"
        />

        <Button
          icon={<Link1Icon />}
          loading={isLoading}
          disabled={isLoading || !selectedTeamSlug}
          onClick={handleClick}
        >
          {isLoading ? 'Connecting…' : 'Connect'}
        </Button>
      </div>
    </div>
  );
}
