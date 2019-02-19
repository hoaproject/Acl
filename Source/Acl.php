<?php

declare(strict_types=1);

/**
 * Hoa
 *
 *
 * @license
 *
 * New BSD License
 *
 * Copyright © 2007-2017, Hoa community. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the Hoa nor the names of its contributors may be
 *       used to endorse or promote products derived from this software without
 *       specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS AND CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

namespace Hoa\Acl;

use Hoa\Consistency;
use Hoa\Graph;

/**
 * Class \Hoa\Acl.
 *
 * The ACL main class. It contains all users, groups, and services collections.
 * It also proposes to check if a user is allow or not to do an action according
 * to its groups and services.
 */
class Acl
{
    /**
     * Propagate delete.
     *
     * @const bool
     */
    const DELETE_CASCADE  = Graph::DELETE_CASCADE;

    /**
     * Restrict delete.
     *
     * @const bool
     */
    const DELETE_RESTRICT = Graph::DELETE_RESTRICT;

    /**
     * All users.
     *
     * @var array
     */
    protected $_users    = [];

    /**
     * Underlying graph.
     *
     * @var ?Graph
     */
    protected $_groups   = null;

    /**
     * All services.
     *
     * @var array
     */
    protected $_services = [];



    /**
     * Built an access control list.
     */
    public function __construct()
    {
        $this->_groups = new Graph\AdjacencyList(Graph\AdjacencyList::DISALLOW_LOOP);

        return;
    }

    /**
     * Add a group, i.e. add a node in the underlying graph.
     */
    public function addGroup(Group $group, array $parents = []): self
    {
        foreach ($parents as $parent) {
            if (!($parent instanceof Group)) {
                throw new Exception(
                    'Group %s must be an instance of Hoa\Acl\Group.',
                    0,
                    $parent
                );
            }
        }

        try {
            $this->getGroups()->addNode($group, $parents);
        } catch (Graph\Exception $e) {
            throw new Exception($e->getMessage(), $e->getCode());
        }

        return $this;
    }

    /**
     * Delete a group, i.e. delete a node in the underlying graph.
     */
    public function deleteGroup(Group $group, bool $propagate = self::DELETE_RESTRICT): self
    {
        try {
            $this->getGroups()->deleteNode($group, $propagate);
        } catch (Graph\Exception $e) {
            throw new Exception(
                'Apparently it is not possible to delete the group %s, ' .
                'probably because it has at least one child.',
                1,
                $group->getId(),
                $e
            );
        }

        return $this;
    }

    /**
     * Check if a group exists or not, i.e. if a node in the underlying graph
     * exists.
     */
    public function groupExists($groupId): bool
    {
        return $this->getGroups()->nodeExists($groupId);
    }

    /**
     * Get a specific group, i.e. a specific node in the underlying graph.
     */
    protected function getGroup(string $groupId): Group
    {
        if (false === $this->groupExists($groupId)) {
            throw new Exception('Group %s does not exist.', 2, $groupId);
        }

        return $this->getGroups()->getNode($groupId);
    }

    /**
     * Get all groups, i.e. get the underlying graph.
     */
    protected function getGroups(): Graph
    {
        return $this->_groups;
    }

    /**
     * Attach one or more permissions to a group.
     */
    public function allow(Group $group, array $permissions = []): self
    {
        $id = $group->getId();

        if (false === $this->groupExists($id)) {
            throw new Exception(
                'Group %s is not declared in the current ACL instance, ' .
                'cannot add permissions.',
                3,
                $id
            );
        }

        $group->addPermissions($permissions);

        return $this;
    }

    /**
     * Detach one or more permission to a group.
     */
    public function deny(Group $group, array $permissions = []): self
    {
        $id = $group->getId();

        if (false === $this->groupExists($id)) {
            throw new Exception(
                'Group %s is not declared in the current ACL instance, ' .
                'cannot delete permissions.',
                4,
                $id
            );
        }

        $group->deletePermissions($permissions);

        return $this;
    }

    /**
     * Check if a user is allowed to do something according to the permission.
     */
    public function isAllowed(
        $userId,
        $permissionId,
        $serviceId         = null,
        Assertable $assert = null
    ): bool {
        if ($userId instanceof User) {
            $userId = $userId->getId();
        }

        if ($permissionId instanceof Permission) {
            $permissionId = $permissionId->getId();
        }

        if ($serviceId instanceof Service) {
            $serviceId = $serviceId->getId();
        }

        $groups = [];
        $user   = null;

        foreach ($this->getGroups() as $group) {
            if (true === $group->userExists($userId)) {
                $groups[] = $group;

                if (null === $user) {
                    $user = $group->getUser($userId);
                }
            }
        }

        if (empty($groups)) {
            return false;
        }

        $serviceIsOwned  = false;
        $serviceIsShared = false;
        $verdict         = false;

        foreach ($groups as $group) {
            if (null !== $serviceId && false === $serviceIsShared) {
                $serviceIsShared = $group->serviceExists($serviceId);
            }

            $iterator = new Graph\Iterator\BackwardBreadthFirst(
                $this->getGroups(),
                $group
            );

            foreach ($iterator as $_group) {
                if (true === $_group->permissionExists($permissionId)) {
                    $verdict = true;

                    break 2;
                }
            }
        }

        if (null !== $serviceId) {
            $serviceIsOwned = $user->serviceExists($serviceId);

            if (false === $serviceIsOwned &&
                false === $serviceIsShared) {
                $verdict = false;
            }
        }

        if (false === $verdict) {
            return false;
        }

        if (null === $assert) {
            return true;
        }

        return $assert->assert($userId, $permissionId, $serviceId);
    }

    /**
     * Transform the groups to DOT language.
     */
    public function __toString(): string
    {
        return $this->getGroups()->__toString();
    }
}

/**
 * Flex entity.
 */
Consistency::flexEntity(Acl::class);
