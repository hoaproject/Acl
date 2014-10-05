<?php

/**
 * Hoa
 *
 *
 * @license
 *
 * New BSD License
 *
 * Copyright © 2007-2014, Ivan Enderlin. All rights reserved.
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

use Hoa\Core;
use Hoa\Graph;


/**
 * Class \Hoa\Acl.
 *
 * The ACL main class. It contains all users, groups, and resources collections.
 * It also proposes to check if a user is allow or not to do an action according
 * to its groups, and resources.
 *
 * @author     Ivan Enderlin <ivan.enderlin@hoa-project.net>
 * @copyright  Copyright © 2007-2014 Ivan Enderlin.
 * @license    New BSD License
 */
class Acl
{

    /**
     * Propagate delete.
     *
     * @const bool
     */
    const DELETE_CASCADE = true;

    /**
     * Restricte delete.
     *
     * @const bool
     */
    const DELETE_RESTRICT = false;

    /**
     * Instance of \Hoa\Acl, make a singleton.
     *
     * @var \Hoa\Acl object
     */
    private static $_instance = null;

    /**
     * Array of all users.
     *
     * @var \Hoa\Acl array
     */
    protected $users = [];

    /**
     * Graph of groups.
     *
     * @var \Hoa\Acl \Hoa\Graph
     */
    protected $groups = null;

    /**
     * Array of all resources.
     *
     * @var \Hoa\Acl array
     */
    protected $resources = [];


    /**
     * Built an access control list.
     *
     * @access  private
     * @param   bool $loop Allow or not loop. Please, see the \Hoa\Graph
     *                            class.
     * @return  void
     */
    private function __construct($loop = Graph::DISALLOW_LOOP)
    {

        $this->groups = Graph::getInstance(
            Graph::TYPE_ADJACENCYLIST,
            $loop
        );
    }

    /**
     * Get the instance of \Hoa\Acl, make a singleton.
     *
     * @access  public
     * @param   bool $loop Allow or not loop. Please, see the \Hoa\Graph
     *                            class.
     * @return  object
     */
    public static function getInstance($loop = Graph::DISALLOW_LOOP)
    {

        if (null === self::$_instance)
            self::$_instance = new self($loop);

        return self::$_instance;
    }

    /**
     * Add a user.
     *
     * @access  public
     * @param   \Hoa\Acl\User $user User to add.
     * @return  void
     * @throw   \Hoa\Acl\Exception
     */
    public function addUser(User $user)
    {

        if ($this->userExists($user->getId()))
            throw new Exception(
                'User %s is already registried.', 0, $user->getId());

        $this->users[$user->getId()] = $user;

        return;
    }

    /**
     * Delete a user.
     *
     * @access  public
     * @param   mixed $user User to delete.
     * @return  void
     */
    public function deleteUser($user)
    {

        if ($user instanceof User)
            $user = $user->getId();

        unset($this->users[$user]);

        return;
    }

    /**
     * Add a group.
     *
     * @access  public
     * @param   \Hoa\Acl\Group $group Group to add.
     * @param   mixed $inherit Group inherit permission from (should
     *                                      be the group ID or the group
     *                                      instance).
     * @return  void
     * @throw   \Hoa\Acl\Exception
     */
    public function addGroup(Group $group, $inherit = [])
    {

        if (!is_array($inherit))
            $inherit = [$inherit];

        foreach ($inherit as $foo => &$in)
            if ($in instanceof Group)
                $in = $in->getId();

        try {

            $this->getGroups()->addNode($group, $inherit);
        } catch (Graph\Exception $e) {

            throw new Exception($e->getMessage(), $e->getCode());
        }

        return;
    }

    /**
     * Delete a group.
     *
     * @access  public
     * @param   mixed $groupId The group ID.
     * @param   bool $propagate Propagate the erasure.
     * @return  void
     * @throw   \Hoa\Acl\Exception
     */
    public function deleteGroup($groupId, $propagate = self::DELETE_RESTRICT)
    {

        if ($groupId instanceof Group)
            $groupId = $groupId->getId();

        try {

            $this->getGroups()->deleteNode($groupId, $propagate);
        } catch (Graph\Exception $e) {

            throw new Exception($e->getMessage(), $e->getCode());
        }

        foreach ($this->getUsers() as $userId => $user)
            $user->deleteGroup($groupId);

        return;
    }

    /**
     * Add a resource.
     *
     * @access  public
     * @param   \Hoa\Acl\Resource $resource Resource to add.
     * @return  void
     * @throw   \Hoa\Acl\Exception
     */
    public function addResource(Resource $resource)
    {

        if ($this->resourceExists($resource->getId()))
            throw new Exception(
                'Resource %s is already registried.', 1, $resource->getId());

        $this->resources[$resource->getId()] = $resource;

        return;
    }

    /**
     * Delete a resource.
     *
     * @access  public
     * @param   mixed $resource Resource to delete.
     * @return  void
     */
    public function deleteResource($resource)
    {

        if ($resource instanceof Resource)
            $resource = $resource->getId();

        unset($this->resources[$resource]);

        return;
    }

    /**
     * Allow a group to make an action according to permissions.
     *
     * @access  public
     * @param   mixed $groupId The group ID.
     * @param   array $permissions Collection of permissions.
     * @return  bool
     * @throw   \Hoa\Acl\Exception
     */
    public function allow($groupId, $permissions = [])
    {

        if (false === $this->groupExists($groupId))
            throw new Exception(
                'Group %s does not exist.', 2, $groupId);

        $this->getGroups()->getNode($groupId)->addPermission($permissions);

        foreach ($this->getGroups()->getChild($groupId) as $subGroupId => $group)
            $this->allow($subGroupId, $permissions);

        return;
    }

    /**
     * Deny a group to make an action according to permissions.
     *
     * @access  public
     * @param   mixed $groupId The group ID.
     * @param   array $permissions Collection of permissions.
     * @return  bool
     * @throw   \Hoa\Acl\Exception
     */
    public function deny($groupId, $permissions = [])
    {

        if ($groupId instanceof Group)
            $groupId = $groupId->getId();

        if (false === $this->groupExists($groupId))
            throw new Exception(
                'Group %s does not exist.', 3, $groupId);

        $this->getGroups()->getNode($groupId)->deletePermission($permissions);

        foreach ($this->getGroups()->getChild($groupId) as $subGroupId => $group)
            $this->deny($subGroupId, $permissions);

        return;
    }

    /**
     * Check if a user is allowed to reach a action according to the permission.
     *
     * @access  public
     * @param   mixed $user User to check (should be the user ID or
     *                                 the user instance).
     * @param   mixed $permission List of permission (should be permission
     *                                 ID, permission instance).
     * @return  bool
     * @throw   \Hoa\Acl\Exception
     */
    public function isAllowed($user, $permission, $resource = null,
                              IAcl\Assert $assert = null)
    {

        if ($user instanceof User)
            $user = $user->getId();

        if ($permission instanceof Permission)
            $permission = $permission->getId();

        if (is_array($permission))
            throw new Exception(
                'Should check one permission, not a list of permissions.', 4);

        if (null !== $resource
            && !($resource instanceof Resource)
        )
            $resource = $this->getResource($resource);

        $user = $this->getUser($user);
        $out = false;

        if (null !== $resource
            && false === $resource->userExists($user->getId())
        )
            return false;

        foreach ($user->getGroups() as $foo => $groupId)
            $out |= $this->isGroupAllowed($groupId, $permission);

        $out = (bool)$out;

        if (null === $assert)
            return $out;

        return $out && $assert->assert();
    }

    /**
     * Check if a group is allowed to reach a action according to the permission.
     *
     * @access  public
     * @param   mixed $group Group to check (should be the group ID or
     *                                 the group instance).
     * @param   mixed $permission List of permission (should be permission
     *                                 ID, permission instance).
     * @return  bool
     * @throw   \Hoa\Acl\Exception
     */
    public function isGroupAllowed($group, $permission)
    {

        if ($group instanceof Group)
            $group = $group->getId();

        if ($permission instanceof Permission)
            $permission = $permission->getId();

        if (is_array($permission))
            throw new \Exception(
                'Should check one permission, not a list of permissions.', 5);

        if (false === $this->groupExists($group))
            throw new Exception(
                'Group %s does not exist.', 6, $group);

        return $this->getGroups()
            ->getNode($group)
            ->permissionExists($permission);
    }

    /**
     * Check if a user exists or not.
     *
     * @access  public
     * @param   string $userId The user ID.
     * @return  bool
     */
    public function userExists($userId)
    {

        if ($userId instanceof User)
            $userId = $userId->getId();

        return isset($this->users[$userId]);
    }

    /**
     * Check if a group exists or not.
     *
     * @access  public
     * @param   string $groupId The group ID.
     * @return  bool
     */
    public function groupExists($groupId)
    {

        if ($groupId instanceof Group)
            $groupId = $groupId->getId();

        return $this->getGroups()->nodeExists($groupId);
    }

    /**
     * Check if a resource exists or not.
     *
     * @access  public
     * @param   string $resourceId The resource ID.
     * @return  bool
     */
    public function resourceExists($resourceId)
    {

        if ($resourceId instanceof Resource)
            $resourceId = $resourceId->getId();

        return isset($this->resources[$resourceId]);
    }

    /**
     * Get a specific user.
     *
     * @access  public
     * @param   string $userId The user ID.
     * @return  \Hoa\Acl\User
     * @throw   \Hoa\Acl\Exception
     */
    public function getUser($userId)
    {

        if (false === $this->userExists($userId))
            throw new Exception(
                'User %s does not exist.', 7, $userId);

        return $this->users[$userId];
    }

    /**
     * Get all users.
     *
     * @access  protected
     * @return  array
     */
    protected function getUsers()
    {

        return $this->users;
    }

    /**
     * Get a specific group.
     *
     * @access  public
     * @param   string $groupId The group ID.
     * @return  \Hoa\Acl\Group
     * @throw   \Hoa\Acl\Exception
     */
    public function getGroup($groupId)
    {

        if (false === $this->groupExists($groupId))
            throw new Exception(
                'Group %s does not exist.', 8, $groupId);

        return $this->getGroups()->getNode($groupId);
    }

    /**
     * Get all groups, i.e. get the groups graph.
     *
     * @access  protected
     * @return  \Hoa\Graph
     */
    protected function getGroups()
    {

        return $this->groups;
    }

    /**
     * Get a specific resource.
     *
     * @access  public
     * @param   string $resourceId The resource ID.
     * @return  \Hoa\Acl\Resource
     * @throw   \Hoa\Acl\Exception
     */
    public function getResource($resourceId)
    {

        if (false === $this->resourceExists($resourceId))
            throw new Exception(
                'Resource %s does not exist.', 9, $resourceId);

        return $this->resources[$resourceId];
    }

    /**
     * Get all resources.
     *
     * @access  protected
     * @return  array
     */
    protected function getResources()
    {

        return $this->getResources;
    }

    /**
     * Transform the groups to DOT language.
     *
     * @access  public
     * @return  string
     */
    public function __toString()
    {

        return $this->getGroups()->__toString();
    }
}

/**
 * Flex entity.
 */
Core\Consistency::flexEntity('Hoa\Acl\Acl');

